// main.go
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

var methods = [3]string{"GET", "POST", "PUT"}

const MinBody = 10
const MaxBody = 200

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

type StatSample struct {
	LatencyMs []float64
	SentBytes int
	RecvBytes int
	Messages  int
}

type Metrics struct {
	Latency    []float64
	SentBytes  int64
	RecvBytes  int64
	MessageIn  int64
	MessageOut int64
	mu         sync.Mutex
}

func requestToStringBuffer(req *http.Request) (string, error) {
	reqBytes, err := httputil.DumpRequest(req, true)
	if err != nil {
		return "", err
	}
	return string(reqBytes), nil
}

func stringBufferToRequest(reqStr string) (*http.Request, error) {
	reader := bufio.NewReader(bytes.NewBufferString(reqStr))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func responseToStringBuffer(resp *http.Response) (string, error) {
	respBytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return "", err
	}
	return string(respBytes), nil
}

func stringBufferToResponse(respStr string) (*http.Response, error) {

	if strings.HasPrefix(respStr, "error") {
		return nil, errors.New("Got error from server")
	}

	reader := bufio.NewReader(bytes.NewBufferString(respStr))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		log.Printf("stringBufferToResponse error on string recived %s with error = %v", respStr, err)
		return nil, err
	}
	return resp, nil
}

func responseToString(resp *http.Response) (string, error) {
	var builder strings.Builder

	// Write the status line
	builder.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))

	// Write the headers
	for key, values := range resp.Header {
		for _, value := range values {
			builder.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	// Write a blank line to separate headers from the body
	builder.WriteString("\r\n")

	// Write the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	builder.Write(body)

	return builder.String(), nil
}

//collect metrix data for processing
//func (m *Metrics) Record(latency float64, sent int, recv int) {
//	m.mu.Lock()
//	defer m.mu.Unlock()
//	m.Latency = append(m.Latency, latency)
//	m.SentBytes += sent
//	m.RecvBytes += recv
//	m.Messages++
//}

func (m *Metrics) Stats() (avg, median, stddev, skew, p95, p99 float64) {
	m.mu.Lock()
	values := append([]float64(nil), m.Latency...)
	m.Latency = nil
	m.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.Latency)
	if n == 0 {
		return
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	avg = sum / float64(n)
	sort.Float64s(values)
	if n%2 == 0 {
		median = (values[n/2] + values[n/2+1]) / 2
	} else {
		median = values[n/2]
	}
	p95 = values[int(0.95*float64(n))]
	p99 = values[int(0.99*float64(n))-1]
	var variance float64
	var s3 float64
	for _, v := range values {
		d := v - avg
		sd := d * d //power of 2
		variance += sd
		s3 += sd * d // power of 3
	}
	variance /= float64(n)
	stddev = math.Sqrt(variance)
	g := math.Sqrt(float64(n)) * s3 / math.Pow(variance, 1.5)
	skew = math.Sqrt(float64(n*(n-1))) * g / float64(n-2)
	return
}

//func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
//	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
//	if err != nil {
//		log.Printf("error in cert, err := tls.LoadX509KeyPair(certFile, keyFile) files %s %s", certFile, keyFile)
//		return nil, err
//	}
//	caCert, err := os.ReadFile(caFile)
//	if err != nil {
//		log.Printf("error read %s", caFile)
//		return nil, err
//	}
//	caCertPool := x509.NewCertPool()
//	caCertPool.AppendCertsFromPEM(caCert)
//	return &tls.Config{
//		Certificates:       []tls.Certificate{cert},
//		RootCAs:            caCertPool,
//		InsecureSkipVerify: true, // for testing only
//		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
//			for _, chain := range verifiedChains {
//				for _, cert := range chain {
//					log.Printf("the server subject is : %s", cert.Subject.String())
//					return nil
//				}
//				return nil
//			}
//			return nil
//		},
//	}, nil
//}

func generateRandomAlphanumeric(length int) []byte {
	b := make([]byte, length)
	charsetSize := len(charset)
	for i := range b {
		b[i] = charset[rand.Intn(charsetSize)]
	}
	return b
}

func clientWorker(mtlsDialer websocket.Dialer,
	server string,
	port int,
	clientID int,
	messagesPerConn int,
	msgInterval time.Duration,
	ch chan StatSample,
	cwg *sync.WaitGroup) {
	log.Printf("Client %d: started", clientID)
	defer cwg.Done()

	//url := fmt.Sprintf("wss://%s:%d/ws/%d", server, port, clientID)
	//url := fmt.Sprintf("ws://localhost:8020/ws/%s", clientID)
	url := fmt.Sprintf("ws://localhost:%d/ws/by-id/%d", port, clientID) //ws/by-id/
	//log.Printf("Client %d: Connection to %s: started", clientID, url)
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	//conn, _, err := mtlsDialer.Dial(url, nil)
	//conn, _, err := mtlsDialer.Dial(url, http.Header{"Connection": {"upgrade"}})
	if err != nil {
		log.Printf("Client %d: Connection failed to %s: %v", clientID, url, err)
		return
	}
	//log.Printf("Client %d: Connection to %s: after dial", clientID, url)
	rand.NewSource(time.Now().UnixNano())
	for i := 0; i < messagesPerConn; i++ {
		nano := time.Now().UnixNano()
		t0 := time.Unix(0, nano)

		var body []byte // later i may use empty as well
		body = generateRandomAlphanumeric(rand.Intn((MaxBody - MinBody + 1) + MinBody))
		method := methods[rand.Intn(3)]
		request, err := http.NewRequest(method, fmt.Sprintf("/%d/msgNumber/%d", int64(clientID), i), bytes.NewBuffer(body))
		request.Header.Add("Content-Type", "application/text")
		request.Header.Add("Content-Length", strconv.Itoa(len(body)))
		request.Header.Add("X-Client-ID", strconv.FormatInt(int64(clientID), 10))
		request.Header.Add("X-Start-Time", strconv.FormatInt(nano, 10))

		msg, err := requestToStringBuffer(request)
		if err != nil {
			log.Printf("requestToStringBuffer filed to convert %v", err)
			break
		}

		//log.Printf("Client %d: Connection to %s: sending msg %s", clientID, url, msg)

		err = conn.WriteMessage(websocket.TextMessage, []byte(msg))
		if err != nil {
			log.Printf("Write failed: %v", err)
			break
		}
		//log.Printf("Client %d: Connection to %s: after send message", clientID, url)

		type_, reply, err := conn.ReadMessage()
		if err != nil || type_ != websocket.TextMessage {
			log.Printf("Read failed: %v", err)
			break
		}

		//latency := float64(time.Since(t0).Milliseconds())
		response, err := stringBufferToResponse(string(reply))
		if err != nil || type_ != websocket.TextMessage {
			//log.Printf("Failed to convert to http response: %v", err)
			continue
		}
		//resp, _ := responseToString(response)
		//log.Printf("Client %d: Connection to %s: message received back %s", clientID, url, resp)

		bodySize := response.ContentLength
		if int64(len(reply)) < bodySize {
			log.Printf("Srange shouldent happend")
		}
		ch <- StatSample{
			//LatencyMs: latency,
			SentBytes: len(msg),
			RecvBytes: len(reply),
		}
		//metrics.Record(latency, len(msg), len(reply))
		log.Printf("Loop took without sleap %v, for client %d", time.Since(t0).Milliseconds(), clientID)
		time.Sleep(msgInterval)
		//log.Printf("Loop took with sleap %v, for client %d", time.Since(t0).Milliseconds(), clientID)
	}
	err = conn.Close()
	if err != nil {
		log.Printf("Client %d: Connection close failed to %s: %v", clientID, url, err)
	}

}

type Connection struct {
	Connection *websocket.Conn
	ClientId   int
	Url        string
}

/*
*
 */
func createConnection(connections *[]Connection, dialer *websocket.Dialer, port int, clientID int, baseUrl string) error {
	var connection Connection
	var err error
	connection.Url = fmt.Sprintf(baseUrl, port, clientID)
	connection.Connection, _, err = dialer.Dial(connection.Url, nil)
	if err != nil {
		log.Printf("Client %d: Connection failed to %s: %v", clientID, connection.Url, err)
		return err
	}
	connection.ClientId = clientID
	*connections = append(*connections, connection)
	return nil
}

func closeConnection(connections []Connection) {
	for _, conn := range connections {
		err := conn.Connection.Close()
		if err != nil {
			log.Printf("Client %d: Connection close failed to close: %v", conn.ClientId, err)
		}
	}
}

func sendMessage(connections []Connection, messageNumber int, ch chan StatSample) {
	var body []byte // later i may use empty as well
	body = generateRandomAlphanumeric(rand.Intn((MaxBody - MinBody + 1) + MinBody))
	method := methods[rand.Intn(3)]
	var sentSize int
	sentSize = 0
	i := 0
	for _, conn := range connections {
		//log.Printf("sendMessage %d", i)
		nano := time.Now().UnixNano()
		//t0 := time.Unix(0, nano)

		request, err := http.NewRequest(method, fmt.Sprintf("/%d/msgNumber/%d", int64(conn.ClientId), messageNumber), bytes.NewBuffer(body))
		request.Header.Add("Content-Type", "application/text")
		request.Header.Add("Content-Length", strconv.Itoa(len(body)))
		request.Header.Add("X-Client-ID", strconv.FormatInt(int64(conn.ClientId), 10))
		request.Header.Add("X-Start-Time", strconv.FormatInt(nano, 10))

		msg, err := requestToStringBuffer(request)
		if err != nil {
			log.Printf("requestToStringBuffer filed to convert %v", err)
			break
		}

		err = conn.Connection.WriteMessage(websocket.TextMessage, []byte(msg))
		if err != nil {
			log.Printf("Write failed for client %d error : %v", conn.ClientId, err)
			//break
			//todo count failes
		}
		i++
		sentSize += len(msg)
	}
	ch <- StatSample{
		LatencyMs: nil,
		SentBytes: sentSize,
		RecvBytes: 0,
		Messages:  i,
	}
}

func receiveMessage(connections []Connection, ch chan StatSample) {
	var latency []float64

	rcvBytes := 0
	i := 0

	for _, conn := range connections {
		type_, reply, err := conn.Connection.ReadMessage()
		nano := time.Now().UnixNano()

		if err != nil || type_ != websocket.TextMessage {
			log.Printf("Read failed: %v", err)

		}
		response, err := stringBufferToResponse(string(reply))
		if err != nil || type_ != websocket.TextMessage {
			//log.Printf("Failed to convert to http response: %v", err)
			continue
		}

		timeStr := response.Header.Get("X-Start-Time")
		startTime, err := strconv.ParseInt(timeStr, 10, 64) // base 10, 64-bit
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		log.Printf("start time %d, end time %d, latency %d", startTime, nano, (nano-startTime)/1000000)
		latency = append(latency, float64(nano-startTime))
		//resp, _ := responseToString(response)

		bodySize := response.ContentLength
		if int64(len(reply)) < bodySize {
			log.Printf("Srange shouldent happend")
		}
		rcvBytes += len(reply)
		i++
	}
	ch <- StatSample{
		LatencyMs: latency,
		SentBytes: 0,
		RecvBytes: rcvBytes,
		Messages:  i,
	}

}

func startClient(clientID int,
	ch chan StatSample,
	//tlsConfig *tls.Config,
	ports []int,
	messagesPerConn int,
	msgInterval time.Duration,
	server string,
	wg *sync.WaitGroup) {
	defer wg.Done()
	// build dialer with the MTLS
	//mtlsDialer := websocket.Dialer{
	//	TLSClientConfig: tlsConfig,
	//}
	//mtlsDialer := websocket.Dialer{
	//	//TLSClientConfig: tlsConfig,
	//}

	var connections []Connection
	dailer := websocket.DefaultDialer
	for _, port := range ports {
		log.Printf("connect client %d on port %d", clientID, port)

		err := createConnection(&connections, dailer, port, clientID, "ws://localhost:%d/ws/by-id/%d")
		if err != nil {
			log.Printf("Error tring to connect client %d", clientID)
			panic(err)
		}
		clientID += 1

	}

	for i := 0; i < messagesPerConn; i++ {
		nano := time.Now().UnixNano()
		t0 := time.Unix(0, nano)
		sendMessage(connections, i, ch)
		receiveMessage(connections, ch)
		time.Since(t0).Milliseconds()
		interval := time.Since(t0)
		if (msgInterval - interval) < 0 {
			time.Sleep(msgInterval)
		} else {
			time.Sleep(msgInterval - interval)
		}
	}

	closeConnection(connections)

	//var cwg sync.WaitGroup
	//var i int
	//i = 0
	//for _, port := range ports {
	//	cwg.Add(1)
	//	i++
	//	//log.Printf("Starting Client %d", clientID)
	//	go clientWorker(mtlsDialer, server, port, clientID, messagesPerConn, msgInterval, ch, &cwg)
	//	log.Printf("started Client %d", clientID)
	//	clientID += 1
	//}
	//cwg.Wait()
	//log.Printf("exit Client %d", clientID)

}

func main() {
	// Read config from ENV
	numClients, _ := strconv.Atoi(getEnv("NUM_CLIENTS", "10"))
	messagesPerClient, _ := strconv.Atoi(getEnv("MESSAGES_PER_CLIENT", "100"))
	msgRate, _ := strconv.ParseFloat(getEnv("MESSAGES_PER_SECOND", "1"), 64)
	server := getEnv("SERVER_ADDR", "localhost")
	startPort, _ := strconv.Atoi(getEnv("START_PORT", "8020"))
	portCount, _ := strconv.Atoi(getEnv("PORT_COUNT", "1"))
	//ca := getEnv("CA_CERT", "ca.crt")
	//cert := getEnv("CLIENT_CERT", "client.crt")
	//key := getEnv("CLIENT_KEY", "client.key")
	pushURL := getEnv("PROM_PUSHGATEWAY_URL", "http://localhost:9091")

	// initialize the list of server ports to use
	ports := make([]int, portCount)
	for i := range ports {
		log.Printf("adding port to %d", i)
		ports[i] = startPort + i
	}

	// time to wait between one message to the second one where 0.2 means wait 5 seconds where 5 means 200 milliseconds
	interval := time.Duration(float64(time.Second) / msgRate)
	sampleRate := 5

	//tlsConfig, err := loadTLSConfig(cert, key, ca)
	//if err != nil {
	//	log.Fatalf("TLS config error: %v", err)
	//}

	metrics := &Metrics{}
	statsChan := make(chan StatSample, 100000)
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		log.Printf("Start clients %d", i*portCount)
		go startClient(i*portCount, statsChan, ports, messagesPerClient, interval, server, &wg)
	}

	go func() { // collects stats for later process
		for sample := range statsChan {
			//log.Printf("Stats Sample %v", sample)
			if len(sample.LatencyMs) != 0 {
				metrics.mu.Lock()
				metrics.Latency = append(metrics.Latency, sample.LatencyMs...)
				log.Printf("recived %d", len(metrics.Latency))
				metrics.mu.Unlock()
			}
			if len(sample.LatencyMs) != 0 { //recived messages
				atomic.AddInt64(&metrics.RecvBytes, int64(sample.RecvBytes))
				atomic.AddInt64(&metrics.MessageIn, int64(sample.Messages))
			} else {
				atomic.AddInt64(&metrics.SentBytes, int64(sample.SentBytes))
				atomic.AddInt64(&metrics.MessageOut, int64(sample.Messages))
			}

		}
	}()

	go func() {
		tick := time.NewTicker(time.Duration(sampleRate) * time.Second)
		for range tick.C {
			log.Printf("Stats recived %d", len(metrics.Latency))
			rcvMsgCount := atomic.SwapInt64(&metrics.MessageIn, 0)
			sndMsgCount := atomic.SwapInt64(&metrics.MessageOut, 0)
			sent := atomic.SwapInt64(&metrics.SentBytes, 0)
			recv := atomic.SwapInt64(&metrics.RecvBytes, 0)

			avg, median, sdv, skew, p95, p99 := metrics.Stats() // get statistics results

			rcvMsgRate := float64(rcvMsgCount) / float64(sampleRate)
			sndMsgRate := float64(sndMsgCount) / float64(sampleRate)
			sentRate := float64(sent) / float64(sampleRate)
			recviveRate := float64(recv) / float64(sampleRate)
			log.Printf("[%ds] rcv rate=%.1f/s sent rate=%.1f/s rcv=%.1fK/s snd=%.1fK/s avg=%.2fms med=%.2fms std=%.2f skew=%.2f p95=%.2fms p99=%.2fms",
				sampleRate, rcvMsgRate, sndMsgRate, recviveRate/1000.0, sentRate/1000.0, avg, median, sdv, skew, p95, p99)

			err := push.New(pushURL, "ws_test").
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "rcv_msg_rate_per_second", Help: "Receive Messages per second",
				}, func() float64 { return rcvMsgRate })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "snt_msg_rate_per_second", Help: "Sent Messages per second",
				}, func() float64 { return sndMsgRate })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "Average_latency_ms", Help: "Average latency in ms",
				}, func() float64 { return avg })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "SDV", Help: "SDVs",
				}, func() float64 { return sdv })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "SKEW", Help: "SKEW",
				}, func() float64 { return skew })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "median_latency_ms", Help: "median latency in ms",
				}, func() float64 { return median })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "latency_p95_ms", Help: "95th percentile latency",
				}, func() float64 { return p95 })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "latency_p99_ms", Help: "99th percentile latency",
				}, func() float64 { return p99 })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "Bytes sent", Help: "KB sent from clients per second",
				}, func() float64 { return sentRate / 1000 })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "Bytes Recived", Help: "KB recived from clients per second",
				}, func() float64 { return sentRate / 1000 })).
				Push()
			if err != nil {
				log.Printf("Prometheus push failed: %v", err)
			}

		}
	}()

	wg.Wait()
}
