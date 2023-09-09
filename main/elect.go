package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"npcc/core/identity"
	"npcc/pbgo"
	"time"

	"github.com/spf13/cobra"
	"npcc/core/config"
)

var (
	roleTypeFlag int32
	idFlag       string
)

func electCMD() *cobra.Command {
	electCmd := &cobra.Command{
		Use:   "elect",
		Short: "npcc elect",
		Long:  "npcc elect congress people or member of committee",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			//TODO：用全局的viper获取配置，接下来的子命令可以用全局的viper获取配置
		},
	}

	electCmd.AddCommand(listCMD())
	electCmd.AddCommand(voteCMD())
	electCmd.AddCommand(calloutCMD())
	electCmd.AddCommand(checkCMD())

	return electCmd
}

func list(cmd *cobra.Command) error {
	fmt.Printf("execute elect list cmd\n")
	lc := config.InitLocalConfig(cmd)

	id := identity.Identity{}
	err := id.InitID(lc)
	if err != nil {
		return fmt.Errorf("init identity err: %s", err)
	}

	clientConfig, err := lc.ClientConfig()
	if err != nil {
		return fmt.Errorf("get client config err: %s", err)
	}

	conn, err := clientConfig.Dial(lc.Net.GRPC.ListenAddr)
	client := pbgo.NewElectClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ids, err := client.List(ctx, &pbgo.Empt{})
	if err != nil {
		return fmt.Errorf("list err: %v", err)
	}
	if ids != nil && ids.Num > 0 {
		fmt.Printf("[%s] nodes in the local network list:\n", lc.ID.Name)
		for i, id := range ids.Ids {
			fmt.Printf("%d  %s\n", i, id.Id)
		}
	}
	return nil
}

// ./npcc elect list -c ../test/org1/members/id1/npcc_config.yaml
func listCMD() *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "npcc elect list",
		Long:  "list nodes in network",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return list(cmd)
		},
	}
	return listCmd
}

func vote(cmd *cobra.Command) error {
	lc := config.InitLocalConfig(cmd)

	id := identity.Identity{}
	err := id.InitID(lc)
	if err != nil {
		return fmt.Errorf("init identity err: %s", err)
	}

	if roleTypeFlag < int32(pbgo.Vote_DEPUTY_TO_NPC) || roleTypeFlag > int32(pbgo.Vote_MEM_NPC_COMMITTEE) {
		//选举的必须是节点代表以上的角色
		return fmt.Errorf("elect role must >= DEPUTY_TO_NPC and <= MEM_NPC_COMMITTEE")
	}

	v := &pbgo.Vote{
		Id:   idFlag, //身份id，若未设定，则默认为将Vote发送到的节点的ID
		Role: pbgo.Vote_Role(roleTypeFlag),
	}

	msg := []byte(v.Id + pbgo.Vote_Role_name[roleTypeFlag])
	sig, err := id.Sign(msg, nil)
	if err != nil {
		return fmt.Errorf("sign err: %s", err)
	}
	v.Signature = hex.EncodeToString(sig)

	clientConfig, err := lc.ClientConfig()
	if err != nil {
		return fmt.Errorf("get client config err: %s", err)
	}

	conn, err := clientConfig.Dial(lc.Net.GRPC.ListenAddr)
	if err != nil {
		return fmt.Errorf("dail %s err: %s", lc.Net.GRPC.ListenAddr, err)
	}
	client := pbgo.NewElectClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.Ballot(ctx, v)
	if err != nil {
		return fmt.Errorf("ballot err: %v", err)
	}
	if resp.Status != 0 {
		return fmt.Errorf("ballot err: %s", resp.Msg)
	}
	log.Println("resp:", resp.Msg)
	return nil
}

// ./npcc elect vote -c ../test/org1/members/id1/npcc_config.yaml -r 2 --id QmWJ561CKzp3eZFq2Ni3sedtxf98ZnyjyzQWtWA1wTFF5P
func voteCMD() *cobra.Command {
	voteCmd := &cobra.Command{
		Use:   "vote",
		Short: "npcc elect vote",
		Long:  "vote one people with id and role in a epoch elect",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return vote(cmd)
		},
	}

	flags := voteCmd.Flags()
	flags.Int32VarP(&roleTypeFlag, "role", "r", 0,
		fmt.Sprintf("npcc elect one role of congress: %d", roleTypeFlag))
	flags.StringVar(&idFlag, "id", "", fmt.Sprintf("npcc elect one id for congress: %s", idFlag))

	voteCmd.MarkFlagRequired("role")
	voteCmd.MarkFlagRequired("id")
	return voteCmd
}

func callout(cmd *cobra.Command) error {
	lc := config.InitLocalConfig(cmd)

	id := identity.Identity{}
	err := id.InitID(lc)
	if err != nil {
		return fmt.Errorf("init identity err: %s", err)
	}

	if roleTypeFlag < int32(pbgo.Vote_DEPUTY_TO_NPC) || roleTypeFlag > int32(pbgo.Vote_MEM_NPC_COMMITTEE) {
		//选举的必须是节点代表以上的角色
		return fmt.Errorf("elect role must >= DEPUTY_TO_NPC and <= MEM_NPC_COMMITTEE")
	}

	v := &pbgo.Vote{
		Role: pbgo.Vote_Role(roleTypeFlag),
	}

	clientConfig, err := lc.ClientConfig()
	if err != nil {
		return fmt.Errorf("get client config err: %s", err)
	}

	conn, err := clientConfig.Dial(lc.Net.GRPC.ListenAddr)
	client := pbgo.NewElectClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.CalloutVote(ctx, v)
	if err != nil {
		return fmt.Errorf("ballot err: %v", err)
	}
	log.Println("Callout Detail Form:")
	if resp.Form != nil {
		log.Println(resp.Form)
	} else {
		log.Println("-----------------")
	}
	return nil
}

func calloutCMD() *cobra.Command {
	calloutCmd := &cobra.Command{
		Use:   "callout",
		Short: "npcc elect callout",
		Long:  "callout for finish one epoch elect",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return callout(cmd)
		},
	}

	flags := calloutCmd.Flags()
	flags.Int32VarP(&roleTypeFlag, "role", "r", 0,
		fmt.Sprintf("npcc elect one role of congress: %d", roleTypeFlag))
	calloutCmd.MarkFlagRequired("role")
	return calloutCmd
}

func check(cmd *cobra.Command) error {
	lc := config.InitLocalConfig(cmd)

	id := identity.Identity{}
	err := id.InitID(lc)
	if err != nil {
		return fmt.Errorf("init identity err: %s", err)
	}

	if roleTypeFlag < int32(pbgo.Vote_DEPUTY_TO_NPC) || roleTypeFlag > int32(pbgo.Vote_MEM_NPC_COMMITTEE) {
		//选举的必须是节点代表以上的角色
		return fmt.Errorf("elect role must >= DEPUTY_TO_NPC and <= MEM_NPC_COMMITTEE")
	}

	v := &pbgo.Vote{
		Role: pbgo.Vote_Role(roleTypeFlag),
	}

	clientConfig, err := lc.ClientConfig()
	if err != nil {
		return fmt.Errorf("get client config err: %s", err)
	}

	conn, err := clientConfig.Dial(lc.Net.GRPC.ListenAddr)
	client := pbgo.NewElectClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.CheckVoteBox(ctx, v)
	if err != nil {
		return fmt.Errorf("ballot err: %v", err)
	}
	log.Println("Callout Detail Form:")
	if resp.Form != nil {
		log.Println(string(resp.Form))
	} else {
		log.Println("-----------------")
	}
	return nil
}

func checkCMD() *cobra.Command {
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "npcc elect check",
		Long:  "check vote status in a epoch elect",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return check(cmd)
		},
	}

	flags := checkCmd.Flags()
	flags.Int32VarP(&roleTypeFlag, "role", "r", 0,
		fmt.Sprintf("npcc elect one role of congress: %d", roleTypeFlag))
	checkCmd.MarkFlagRequired("role")
	return checkCmd
}
