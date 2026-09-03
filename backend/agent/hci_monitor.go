package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type OCSFMetadata struct {
	Version string `json:"version"`
	Product struct {
		Vendor  string `json:"vendor"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"product"`
	TenantUID string `json:"tenant_uid"`
}

type OCSFRFActivity struct {
	Interface       string   `json:"interface"`
	Protocol        string   `json:"protocol"`
	EventType       string   `json:"event_type"`
	PeerMAC         string   `json:"peer_mac"`
	PacketLength    int      `json:"packet_length"`
	PayloadEntropy  float64  `json:"payload_entropy"`
	AnomalousFields []string `json:"anomalous_fields"`
}

type OCSFBluetoothPayload struct {
	Metadata     OCSFMetadata   `json:"metadata"`
	CategoryUID  int            `json:"category_uid"`
	ClassUID     int            `json:"class_uid"`
	SeverityID   int            `json:"severity_id"`
	Time         int64          `json:"time"`
	RFActivity   OCSFRFActivity `json:"rf_activity"`
}

func main() {
	fmt.Println("Starting Bluetooth HCI Driver Monitor Daemon...")
	endpoint := os.Getenv("SIEM_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8000/api/ingest/push"
	}
	
	// Simulated loop for intercepting HCI sockets (AF_BLUETOOTH)
	for {
		time.Sleep(10 * time.Second) // Poll interval
		
		// Simulate a captured malformed packet exceeding MTU (e.g., BlueBorne)
		packetLength := 65535 
		if packetLength > 4096 {
			fmt.Printf("[ALERT] L2CAP Packet Overflow Detected: %d bytes\n", packetLength)
			
			payload := OCSFBluetoothPayload{
				CategoryUID: 6,
				ClassUID:    6001,
				SeverityID:  5, // CRITICAL
				Time:        time.Now().UnixNano() / int64(time.Millisecond),
			}
			payload.Metadata.Version = "1.2.0-custom"
			payload.Metadata.Product.Vendor = "ThreatAnalyser"
			payload.Metadata.Product.Name = "Edge Agent Core"
			payload.Metadata.Product.Version = "8.0.0"
			payload.Metadata.TenantUID = "default"
			
			payload.RFActivity = OCSFRFActivity{
				Interface:       "hci0",
				Protocol:        "L2CAP",
				EventType:       "CONNECTION_REQUEST",
				PeerMAC:         "00:1A:7D:DA:71:11",
				PacketLength:    packetLength,
				PayloadEntropy:  7.91,
				AnomalousFields: []string{"packet_length", "payload_entropy"},
			}
			
			jsonBody, _ := json.Marshal(payload)
			
			resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				fmt.Printf("Failed to push to SIEM: %v\n", err)
			} else {
				fmt.Printf("Pushed OCSF Class 6001 to %s, status: %s\n", endpoint, resp.Status)
				resp.Body.Close()
			}
		}
	}
}
