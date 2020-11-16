package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

// SlackRequestBody slack notification object
type SlackRequestBody struct {
	Username  string `json:"username,omitempty"`
	IconEmoji string `json:"icon_emoji,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Text      string `json:"text,omitempty"`
	Markdown  bool   `json:"mrkdwn,omitempty"`
}

var (
	serverPath   = kingpin.Flag("path", "Webhook server path").Default("/webhook").Short('u').String()
	serverPort   = kingpin.Flag("port", "Webhook server port").Default("9999").Short('p').String()
	serverIP     = kingpin.Flag("server", "Server address").Default("127.0.0.1").Short('h').IP()
	secret       = kingpin.Flag("secret", "Webhook secret").Short('s').String()
	slackHook    = kingpin.Flag("slackHook", "Slack incoming webhook").Short('i').String()
	slackChannel = kingpin.Flag("channel", "Slack channel to post notifications").Short('c').String()
	slackEmoji   = kingpin.Flag("emoji", "Slack notification emoji").Short('e').String()
	slackName    = kingpin.Flag("name", "Slack username").Short('n').String()
	loglevel     = kingpin.Flag("loglevel", "Show debug information").Default("INFO").String()

	errNoSignature      = errors.New("No X-Gophish-Signature header provided")
	errInvalidSignature = errors.New("Invalid signature provided")
)

// SendNotification sends message to webhook
func SendNotification(webhookURL string, payload SlackRequestBody) error {

	slackBody, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewBuffer(slackBody))
	if err != nil {
		log.Error(err)
		return err
	}

	requestDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		log.Error(err)
	}
	log.Debug(string(requestDump))

	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err)
		return err
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	log.Debugf("Slack response: %s %s", resp.Status, buf.String())
	if buf.String() != "ok" {
		log.Error("Non-ok response returned from Slack")
		return errors.New("Non-ok response returned from Slack")
	}
	return nil
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Get the provided signature
	signatureHeader := r.Header.Get("X-Gophish-Signature")
	if signatureHeader == "" {
		log.Errorf("no signature provided in request from %s", r.RemoteAddr)
		http.Error(w, errNoSignature.Error(), http.StatusBadRequest)
		return
	}

	signatureParts := strings.SplitN(signatureHeader, "=", 2)
	if len(signatureParts) != 2 {
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}
	signature := signatureParts[1]

	gotHash, err := hex.DecodeString(signature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	// Copy out the rest of body so we can validate the signature
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Validate the signature
	expectedMAC := hmac.New(sha256.New, []byte(*secret))
	expectedMAC.Write(body)
	expectedHash := expectedMAC.Sum(nil)

	if !hmac.Equal(gotHash, expectedHash) {
		log.Errorf("invalid signature provided. expected %s got %s", hex.EncodeToString(expectedHash), signature)
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		// return
	}

	// Print the request header information(taken from
	// net/http/httputil.DumpRequest)
	buf := &bytes.Buffer{}
	rURI := r.RequestURI
	if rURI == "" {
		rURI = r.URL.RequestURI()
	}

	log.Debugf("%s %s HTTP/%d.%d\r\n", r.Method,
		rURI, r.ProtoMajor, r.ProtoMinor)

	absRequestURI := strings.HasPrefix(r.RequestURI, "http://") || strings.HasPrefix(r.RequestURI, "https://")
	if !absRequestURI {
		host := r.Host
		if host == "" && r.URL != nil {
			host = r.URL.Host
		}
		if host != "" {
			log.Debug("Host: ", host)
		}
	}

	// Print out the payload
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			log.Debug(name, value)
		}
	}

	err = json.Indent(buf, body, "", "    ")
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	message := buf.String()
	log.Debug(message)

	slackMsg := SlackRequestBody{
		Text:      "```\n" + message + "\n```\n",
		Channel:   *slackChannel,
		IconEmoji: ":ghost:",
		Markdown:  true,
		Username:  "Fisherman Slack",
	}

	err = SendNotification(*slackHook, slackMsg)
	if err != nil {
		log.Fatal(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

}

func main() {
	kingpin.Parse()
	ll, err := log.ParseLevel(*loglevel)
	if err != nil {
		ll = log.InfoLevel
	}
	// set global log level
	log.SetLevel(ll)
	addr := net.JoinHostPort(serverIP.String(), *serverPort)
	log.Infof("Webhook server started at %s%s", addr, *serverPath)
	http.ListenAndServe(addr, http.HandlerFunc(webhookHandler))
}
