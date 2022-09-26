package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gin-gonic/gin"
	"github.com/status-im/go-waku/waku/v2/node"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/protobuf"
	"golang.org/x/crypto/pbkdf2"

	"github.com/golang/protobuf/proto"

	v1protocol "github.com/status-im/status-go/protocol/v1"
)

const discoveryTopic = "contact-discovery"

var (
	// The number of partitions.
	nPartitions = big.NewInt(5000)
)

func main() {
	router := gin.Default()
	router.POST("/sendMessage", sendMessage)

	router.Run("localhost:7005")
}

// album represents data about a record album.
type sendMessageRequest struct {
	Message     string `json:"message"`
	Recipient   string `json:"recipient"`
	MessageType string `json:"message_type"`
}

func sendMessage(c *gin.Context) {
	var messageBody sendMessageRequest
	if err := c.BindJSON(&messageBody); err != nil {
		return
	}

	var topic string
	var messageType protobuf.MessageType
	var publicKey ecdsa.PublicKey
	if messageBody.MessageType == "public" {
		topic = messageBody.Recipient
		messageType = protobuf.MessageType_PUBLIC_GROUP
	} else if messageBody.MessageType == "one_to_one" {
		publicKey, err := StrToPublicKey(messageBody.Recipient)
		if err != nil {
			panic(err)
		}
		topic = PartitionedTopic(publicKey)
		messageType = protobuf.MessageType_ONE_TO_ONE
	} else {
		panic(fmt.Sprintf("Invalid Message Type: '%v'", messageBody.MessageType))
	}
	topicBytes := ToTopic(topic)
	contentTopic := ContentTopic(topicBytes)

	testMessage := protobuf.ChatMessage{
		Text:        messageBody.Message,
		ChatId:      topic,
		ContentType: protobuf.ChatMessage_TEXT_PLAIN,
		MessageType: messageType,
		Clock:       uint64(time.Now().Unix()),
		Timestamp:   uint64(time.Now().Unix()),
	}

	encodedPayload, err := proto.Marshal(&testMessage)
	if err != nil {
		panic(err)
	}

	authorKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}

	wrappedPayload, err := v1protocol.WrapMessageV1(encodedPayload, protobuf.ApplicationMetadataMessage_CHAT_MESSAGE, authorKey)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("publicKey.X: '%v'\n", publicKey.X)
	// fmt.Printf("publicKey.Y: '%v'\n", publicKey.Y)
	// fmt.Printf("publicKey.Y.Sign(): '%v'\n", publicKey.Y.Sign())
	// fmt.Printf("publicKey.X.Sign(): '%v'\n", publicKey.X.Sign())

	// The messages need to be encrypted before they're broadcasted
	payload := node.Payload{}
	payload.Data = wrappedPayload

	var keyInfo node.KeyInfo
	if messageBody.MessageType == "public" {
		keyInfo = node.KeyInfo{
			PrivKey: authorKey, // Key used to sign the message
			Kind:    node.Symmetric,
			SymKey:  generateSymKey(topic),
		}
	} else if messageBody.MessageType == "one_to_one" {
		keyInfo = node.KeyInfo{
			PrivKey: authorKey, // Key used to sign the message
			Kind:    node.Asymmetric,
			PubKey:  publicKey,
		}
	}

	payload.Key = &keyInfo
	payloadBytes, err := payload.Encode(1)
	if err != nil {
		panic(err)
	}

	hexEncoded := hex.EncodeToString(payloadBytes)

	url := "http://localhost:8545"
	jsonStr := []byte(fmt.Sprintf(`{ "id": 1, "jsonrpc": "2.0", "method": "post_waku_v2_relay_v1_message", "params": ["", { "payload": "%s", "contentTopic": "%s", "version": 1, "timestamp": %d }] }`, hexEncoded, contentTopic, time.Now().UnixNano()))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
	c.String(200, string(body))
}

func ContentTopic(t []byte) string {
	enc := hexutil.Encode(t)
	return "/waku/1/" + enc + "/rfc26"
}

// ToTopic converts a string to a whisper topic.
func ToTopic(s string) []byte {
	return crypto.Keccak256([]byte(s))[:types.TopicLength]
}

func StrToPublicKey(str string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalPubkey(publicKeyBytes)
}

func PublicKeyToStr(publicKey *ecdsa.PublicKey) string {
	return hex.EncodeToString(crypto.FromECDSAPub(publicKey))
}

func PersonalDiscoveryTopic(publicKey *ecdsa.PublicKey) string {
	return "contact-discovery-" + PublicKeyToStr(publicKey)
}

// PartitionedTopic returns the associated partitioned topic string
// with the given public key.
func PartitionedTopic(publicKey *ecdsa.PublicKey) string {
	partition := big.NewInt(0)
	partition.Mod(publicKey.X, nPartitions)
	return "contact-discovery-" + strconv.FormatInt(partition.Int64(), 10)
}

func ContactCodeTopic(publicKey *ecdsa.PublicKey) string {
	return "0x" + PublicKeyToStr(publicKey) + "-contact-code"
}

func NegotiatedTopic(publicKey *ecdsa.PublicKey) string {
	return "0x" + PublicKeyToStr(publicKey) + "-negotiated"
}

func DiscoveryTopic() string {
	return discoveryTopic
}

func generateSymKey(password string) []byte {
	// AesKeyLength represents the length (in bytes) of an private key
	AESKeyLength := 256 / 8
	return pbkdf2.Key([]byte(password), nil, 65356, AESKeyLength, sha256.New)
}
