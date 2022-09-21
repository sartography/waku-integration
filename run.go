package main

// we have a waku node running via this command and listening for RPC requests on port 8545:
// ./build/waku \
//   --dns-discovery=true \
//   --dns-discovery-url=enrtree://AOGECG2SPND25EEFMAJ5WF3KSGJNSGV356DSTL2YVLLZWIV6SAYBM@test.nodes.status.im \
//   --discv5-discovery=true \
//   --rpc \
//   --rpc-admin

// the goal is to send a request like the following to send a message to a user on the status mobile app:

// curl -v -f -s -X POST -H Content-type:application/json --data '{
//     "id": 1,
//     "jsonrpc": "2.0",
//     "method": "post_waku_v2_relay_v1_message",
//     "params": ["", {
//         "payload": "abcdef112233",
//         "contentTopic": "contentTopicGoesHere",
//         "timestamp": 1257894000000000000,
//         "version": 1
//     }]
//     }' http://localhost:8545

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
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/protobuf"

	// "google.golang.org/protobuf/proto"
	"github.com/golang/protobuf/proto"
	// "github.com/status-im/status-go/protocol/encryption"
	// "github.com/status-im/status-go/protocol/protobuf"
	// "github.com/status-im/status-go/protocol/sqlite"
	v1protocol "github.com/status-im/status-go/protocol/v1"
)

const discoveryTopic = "contact-discovery"

var (
	// The number of partitions.
	nPartitions = big.NewInt(5000)
)

func main() {
	publicKeyString := "04aa379d2661d6358f41b47a866f2674ca987e3398e93318ec08ea58b9f7035df491131a62ad3a469af609df9af58bcad698dac7f01e160130b7e187c60b824973"
	// publicKeyString := "04622248490465b1d0cd5ec48375484682bec9a16f550ffd461cb803d4a8970a88cf8f99390a8e2216012602a9f8a0882ae86d773667d2802939150f3a14f1963a"
	publicKey, err := StrToPublicKey(publicKeyString)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PUKEY: '%v'\n", publicKey.X)
	partitionTopic := PartitionedTopic(publicKey)
	fmt.Printf("PAR TOPIC: '%v'\n", partitionTopic)

	testMessage := protobuf.ChatMessage{
		Text:        "abc123",
		ChatId:      "testing-adamb",
		ContentType: protobuf.ChatMessage_TEXT_PLAIN,
		MessageType: protobuf.MessageType_PRIVATE_GROUP,
		Clock:       154593077368201,
		Timestamp:   1545930773682,
	}
	fmt.Printf("testMessage: '%v'\n", testMessage)

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
	fmt.Printf("wrappedPayload: '%v'\n", wrappedPayload)

	hexEncoded := hex.EncodeToString(wrappedPayload)
	fmt.Printf("hexEncoded: '%v'\n", hexEncoded)
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
