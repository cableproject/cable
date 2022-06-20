package mongolib

import (
	"testing"

	"fmt"

	"github.com/free5gc/smf/monitorhandler/mongolib"
	"go.mongodb.org/mongo-driver/bson"
)

type Trainer struct {
	Name string `json:"name" structs:"name"`
	Age  int    `json:"age" structs:"age"`
	City string `json:"city" structs:"city"`
}

func TestPerfclientGetone(t *testing.T) {
	perfclient := mongolib.PerfClient{"mongodb://192.168.56.155:27017", "test", "trainers"}
	perfclient.ConnectMongoDB()

	filter := bson.M{"name": "Ash"}
	getresult := perfclient.GetOne(filter)
	fmt.Printf("Ash is %d years old.\n", getresult["age"])
}
