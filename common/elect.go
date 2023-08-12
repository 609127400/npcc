package common

type ROLE_TYPE int

var (
	COMMON_PEOPLE     ROLE_TYPE = 0 //群众
	MEM_PARTY         ROLE_TYPE = 1 //党员
	DEPUTY_TO_NPC     ROLE_TYPE = 2 //人大代表
	MEM_NPC_PRESI     ROLE_TYPE = 3 //主席团成员
	MEM_NPC_COMMITTEE ROLE_TYPE = 4 //常委会成员
)
