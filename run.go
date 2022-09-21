package main

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
	"fmt"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"strconv"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
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
	fmt.Printf("PAR TOPIC: '%v'", partitionTopic)
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
