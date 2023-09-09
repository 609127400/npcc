package elect

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"npcc/pbgo"
	"npcc/test/mock"
	"testing"
)

func TestElectBox(t *testing.T) {
	handler := func(data []byte) error { fmt.Println("handled"); return nil }
	logger := mock.GetMockLogger("test")
	bm := NewElectBoxManager(handler, logger)

	role := "DEPUTY_TO_NPC"
	v1 := &pbgo.Vote{Voter: "voter1", Pubkey: "pubkey1", Id: "id1", Role: 2, Signature: "sign1"}
	v2 := &pbgo.Vote{Voter: "voter2", Pubkey: "pubkey2", Id: "id1", Role: 2, Signature: "sign2"}
	v3 := &pbgo.Vote{Voter: "voter3", Pubkey: "pubkey3", Id: "id1", Role: 2, Signature: "sign3"}

	//模拟投票
	err := bm.Vote(v1)
	require.Nil(t, err)
	err = bm.Vote(v2)
	require.Nil(t, err)
	//err = bm.Vote(v3)
	//require.Nil(t, err)

	//模拟check
	_, err = bm.Check(role)
	require.Nil(t, err)

	//模拟callout
	_, err = bm.StopAndReport(role)
	require.Nil(t, err)
	bm.Reset(role)

	//再次投票，查看重置之后Box的功能
	err = bm.Vote(v1)
	require.Nil(t, err)
	err = bm.Vote(v2)
	require.Nil(t, err)
	err = bm.Vote(v3)
	require.Nil(t, err)

}
