package main

// we have a waku node running via this command and listening for RPC requests on port 8545:
/*
./build/waku \
  --dns-discovery=true \
  --dns-discovery-url=enrtree://AOGECG2SPND25EEFMAJ5WF3KSGJNSGV356DSTL2YVLLZWIV6SAYBM@prod.nodes.status.im \
  --discv5-discovery=true \
  --rpc \
  --rpc-admin
*/
// the goal is to send a request like the following to send a message to a user on the status mobile app:

/*
curl -v -f -s -X POST -H Content-type:application/json --data '{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "post_waku_v2_relay_v1_message",
    "params": ["", {
        "payload": "abcdef112233",
        "contentTopic": "contentTopicGoesHere",
        "timestamp": 1257894000000000000,
        "version": 1
    }]
    }' http://localhost:8545
*/

// the following script generates an appropriate contentTopic for a known user's public key.
// We know we need to generate a protobuf ChatMessage and wrap it in a protobuf ApplicationMetadataMessage.
// We're wondering if there is prexisting golang code that does this part that we could borrow to easily get this working.

// import (
// 	"fmt"
// 	"math/big"
// 	"strconv"
// 	"crypto/ecdsa"
// 	"github.com/status-im/status-go/eth-node/crypto"
// 	"github.com/status-im/status-go/eth-node/types"
//
// )
//
// func main() {
// 		getPartitionTopic()
// }
//
// func getPartitionTopic() {
// 	// var publicKey = publicKey.X
// 	var publicKey *big.Int = big.NewInt(12345)
// 	var partitionsNum *big.Int = big.NewInt(5000)
// 	var partition *big.Int = big.NewInt(0).Mod(publicKey, partitionsNum)
//
// 	var partitionTopic = "contact-discovery-" + strconv.FormatInt(partition.Int64(), 10)
//
// 	// var hash []byte = keccak256.New() // partitionTopic)
// 	// var hash keccak256 = keccak256.New() // partitionTopic)
//   partitionTopicByteArray := []byte(partitionTopic)
//
// 	var hash = crypto.Keccak256(partitionTopicByteArray)
// 	fmt.Printf("theHash: '%v'\n", hash)
// 	fmt.Printf("partTopick: '%v'\n", partitionTopic)
// 	var topic = hash[:types.TopicLength]
// 	fmt.Printf("lenght: '%v'\n", types.TopicLength)
//
// 	// var topicLen int = 4
//   //
// 	// if len(hash) < topicLen {
// 	// 	topicLen = len(hash)
// 	// }
//   //
// 	// var topic [4]byte
// 	// for i := 0; i < topicLen; i++ {
// 	// 	topic[i] = hash[i]
// 	// }
// 	fmt.Printf("topicBytes: '%v'\n", topic[:])
// 	fmt.Printf("topic: '%v'\n", string(topic[:]))
// }
//
// func StrToPublicKey(str string) (*ecdsa.PublicKey, error) {
// 	publicKeyBytes, err := hex.DecodeString(str)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return crypto.UnmarshalPubkey(publicKeyBytes)
// }

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
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
	rramosKey := "04ca2cf0599ace5def8543cb53e7fbd1d54ba65ab89f8794a08f9bf0406a7895c8074f380adf47a6692df0217cc81d2c680c6f50ef4149c84901f95c22a76bfa96"
	// jasonKey := "04aa379d2661d6358f41b47a866f2674ca987e3398e93318ec08ea58b9f7035df491131a62ad3a469af609df9af58bcad698dac7f01e160130b7e187c60b824973"
	// kbKey := "04e3ec4eb8a7c6b78f30b25ee2b2c34040ede4b9e51627ac82051bb37c4c3de21da0709bced20619566c545ff7b69fd58b8840cd48a686fffe68608f879bf9155b"
	// mikeKey := "04622248490465b1d0cd5ec48375484682bec9a16f550ffd461cb803d4a8970a88cf8f99390a8e2216012602a9f8a0882ae86d773667d2802939150f3a14f1963a"

	publicKeyString := rramosKey
	publicKey, err := StrToPublicKey(publicKeyString)
	if err != nil {
		panic(err)
	}
	_ = publicKey

	topic := "testrramos" // PartitionedTopic(publicKey)
	topicBytes := ToTopic(topic)
	contentTopic := ContentTopic(topicBytes)

	testMessage := protobuf.ChatMessage{
		Text:        "hey yo 2",
		ChatId:      topic,
		ContentType: protobuf.ChatMessage_TEXT_PLAIN,
		MessageType: protobuf.MessageType_PUBLIC_GROUP,
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

	// The messages need to be encrypted before they're broadcasted
	payload := node.Payload{}
	payload.Data = wrappedPayload
	payload.Key = &node.KeyInfo{
		PrivKey: authorKey, // Key used to sign the message

		// For sending to a public channel
		Kind:   node.Symmetric,
		SymKey: generateSymKey(topic),

		// For 1:1
		// Kind: node.Asymmetric,
		// PubKey: publicKey
	}
	payloadBytes, err := payload.Encode(1)
	if err != nil {
		panic(err)
	}

	hexEncoded := hex.EncodeToString(payloadBytes)

	fmt.Printf(`
	
	curl -v --fail-with-body -s -X POST -H Content-type:application/json --data '{
    "id": 1,
    "jsonrpc": "2.0",
    "method": "post_waku_v2_relay_v1_message",
    "params": ["", {
        "payload": "%s",
        "contentTopic": "%s",
        "version": 1,
		"timestamp": %d
    }]
    }' http://localhost:8545
	
	`, hexEncoded, contentTopic, time.Now().UnixNano())

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
