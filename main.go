// main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

type Metrics struct {
	Latency   []float64
	SentBytes int
	RecvBytes int
	Messages  int
	mu        sync.Mutex
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
	reader := bufio.NewReader(bytes.NewBufferString(respStr))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (m *Metrics) Record(latency float64, sent int, recv int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Latency = append(m.Latency, latency)
	m.SentBytes += sent
	m.RecvBytes += recv
	m.Messages++
}

func (m *Metrics) Stats() (avg, median, stddev, skew float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.Latency)
	if n == 0 {
		return
	}
	values := append([]float64(nil), m.Latency...)
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	avg = sum / float64(n)
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	median = sorted[n/2]
	var variance float64
	for _, v := range values {
		variance += (v - avg) * (v - avg)
	}
	variance /= float64(n)
	stddev = math.Sqrt(variance)
	// skew is rough
	skew = (avg - median) / stddev
	return
}

func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}, nil
}

func startClient(clientID int, metrics *Metrics, tlsConfig *tls.Config, ports []int, messagesPerConn int, msgInterval time.Duration, server string, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, port := range ports {
		url := fmt.Sprintf("wss://%s:%d/ws", server, port)
		conn, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Connection": {"upgrade"}})
		if err != nil {
			log.Printf("Client %d: Connection failed to %s: %v", clientID, url, err)
			continue
		}
		for i := 0; i < messagesPerConn; i++ {
			t0 := time.Now()
			msg := fmt.Sprintf("client-%d-msg-%d", clientID, i)
			err := conn.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				log.Printf("Write failed: %v", err)
				break
			}
			type_, reply, err := conn.ReadMessage()
			if err != nil || type_ != websocket.TextMessage {
				log.Printf("Read failed: %v", err)
				break
			}
			latency := float64(time.Since(t0).Milliseconds())
			metrics.Record(latency, len(msg), len(reply))
			time.Sleep(msgInterval)
		}
		conn.Close()
	}
}

func main() {
	// Read config from ENV
	numClients, _ := strconv.Atoi(os.Getenv("NUM_CLIENTS"))
	messagesPerClient, _ := strconv.Atoi(os.Getenv("MESSAGES_PER_CLIENT"))
	msgRate, _ := strconv.ParseFloat(os.Getenv("MESSAGES_PER_SECOND"), 64)
	server := os.Getenv("SERVER_ADDR")
	startPort, _ := strconv.Atoi(os.Getenv("START_PORT"))
	portCount, _ := strconv.Atoi(os.Getenv("PORT_COUNT"))
	ca := os.Getenv("CA_CERT")
	cert := os.Getenv("CLIENT_CERT")
	key := os.Getenv("CLIENT_KEY")
	pushURL := os.Getenv("PROM_PUSHGATEWAY_URL")

	ports := make([]int, portCount)
	for i := range ports {
		ports[i] = startPort + i
	}
	interval := time.Duration(float64(time.Second) / msgRate)

	tlsConfig, err := loadTLSConfig(cert, key, ca)
	if err != nil {
		log.Fatalf("TLS config error: %v", err)
	}

	metrics := &Metrics{}
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go startClient(i, metrics, tlsConfig, ports, messagesPerClient, interval, server, &wg)
	}

	go func() {
		tick := time.NewTicker(5 * time.Second)
		for range tick.C {
			a, m, s, sk := metrics.Stats()
			log.Printf("Stats: avg=%.2fms med=%.2fms std=%.2f skew=%.2f", a, m, s, sk)
			pusher := push.New(pushURL, "ws_test").Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: "avg_latency_ms", Help: "Average latency in ms",
			}, func() float64 { return a })).
				Collector(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
					Name: "message_count", Help: "Total messages sent",
				}, func() float64 { return float64(metrics.Messages) }))
			err := pusher.Push()
			if err != nil {
				log.Printf("Push failed: %v", err)
			}
		}
	}()

	wg.Wait()
}
