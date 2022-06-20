package mongolib

import (
    "github.com/free5gc/MongoDBLibrary"
    "go.mongodb.org/mongo-driver/bson"
    //"encoding/json"
    //"fmt"
    //"github.com/fatih/structs"

)

type PerfClient struct {
	DBurl    string `json:"dburl"`
	DBname   string `json:"dbname"`
	Collname string `json:"collname"`
}

func (pclient *PerfClient) ConnectDB(dbUrl string, dbName string) {
    MongoDBLibrary.SetMongoDB(dbName, dbUrl)
}

func (pclient *PerfClient) GetOne(collName string, filter bson.M) map[string]interface{}  {
    result := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
    return result
}

func (pclient *PerfClient) PostOne(collName string, filter bson.M, postData map[string]interface{}) bool {
    result := MongoDBLibrary.RestfulAPIPost(collName, filter, postData)
    return result
}
