package utils

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go-difi-loans/logreq"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty"
)

type RestClient interface {
	SetAddress(address string)
	DefaultHeader(accToken string) http.Header
	BasicAuth(username, password string) string
	Execute(id, appId, path string, method string, headers http.Header, payload interface{}, employeeCode string, strict bool) (body []byte, statusCode int, err error)
}

func New(options Options) RestClient {
	httpClient := resty.New()

	if options.SkipTLS {
		httpClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	httpClient.SetTimeout(options.Timeout * time.Second)
	httpClient.SetDebug(options.DebugMode)

	return &client{
		options:    options,
		httpClient: httpClient,
	}
}

type client struct {
	options    Options
	httpClient *resty.Client
}

func (c *client) DefaultHeader(accToken string) http.Header {
	headers := http.Header{}
	// headers.Set("Authorization", "Basic "+c.BasicAuth(username, password))
	token := fmt.Sprintf("%s %s", "Bearer ", accToken)
	headers.Set("Authorization", token)
	return headers
}

func (c *client) SetAddress(address string) {
	c.options.Address = address
}

func (c *client) BasicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (c *client) Execute(id, appId, path string, method string, headers http.Header, payload interface{}, employeeCode string, strict bool) (body []byte, statusCode int, err error) {
	url := c.options.Address + path
	request := c.httpClient.R()
	//temp line for timeout

	type Temp struct {
		BeeverTimeout int `json:"beever_timeout"`
	}
	var temp Temp
	// Open our jsonFile
	jsonFile, err := os.Open("conf/timeout.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened timeout.json")
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &temp)
	defer jsonFile.Close()
	c.httpClient.SetTimeout(time.Duration(temp.BeeverTimeout) * time.Millisecond)
	log.Println("==============TIMEOUT============", c.httpClient.GetClient().Timeout)

	// end line timeout testing temp

	// Set header
	for h, val := range headers {
		request.Header[h] = val
	}
	if headers["Content-Type"] == nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if strict {
		tempToken, _ := GetAccToken("", employeeCode)
		token := strings.Trim(tempToken, `"`)
		beeverToken := fmt.Sprintf("%s %s", "Bearer", token)
		request.Header.Set("Authorization", beeverToken)
	}

	// Set body
	switch request.Header.Get("Content-Type") {
	case "application/json":
		request.SetBody(payload)
		logreq.LogRequestHTTP(id, appId, url, method, request.Body, request.Header)
	case "application/x-www-form-urlencoded":
		var formData map[string]string
		ObjectToObject(payload, &formData)
		logreq.LogRequestHTTP(id, appId, url, method, request.FormData, request.Header)
		request.SetFormData(formData)
	}

	startTime := time.Now()

	var httpResp *resty.Response
	var httpErr error
	switch method {
	case http.MethodPost:
		{
			httpResp, httpErr = request.Post(url)
		}
	case http.MethodDelete:
		{
			httpResp, httpErr = request.Delete(url)
		}
	case http.MethodGet:
		{
			httpResp, httpErr = request.Get(url)
		}
	case http.MethodPut:
		{
			httpResp, httpErr = request.Put(url)
		}
	case http.MethodOptions:
		{
			httpResp, httpErr = request.Options(url)
		}
	}

	if httpResp != nil {
		body = httpResp.Body()
	}

	if httpResp != nil && httpResp.StatusCode() != 0 {
		statusCode = httpResp.StatusCode()
	}

	switch httpResp.Header().Get("Content-Type") {
	case "application/json":
		var result interface{}
		json.Unmarshal(body, &result)
		logreq.LogResponseHttp(id, appId, startTime, statusCode, url, method, result)
	default:
		logreq.LogResponseHttp(id, appId, startTime, statusCode, url, method, string(body))
	}

	if statusCode == http.StatusOK {
		return body, statusCode, nil
	}

	return body, statusCode, httpErr
}
