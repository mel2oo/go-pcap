package ftp

type CMD string

// FTP COMMANDS
const (
	// ACCESS CONTROL COMMANDS
	Username                CMD = "USER"
	Password                CMD = "PASS"
	Account                 CMD = "ACCT"
	ChangeWorkingDirectory  CMD = "CWD"
	ChangeToParentDirectory CMD = "CDUP"
	StructureMount          CMD = "SMNT"
	Reinitialize            CMD = "REIN"
	Logout                  CMD = "QUIT"

	// Transfer Parameter Commands
	DataPort           CMD = "PORT"
	Passive            CMD = "PASV"
	RepresentationType CMD = "TYPE"
	FileStructure      CMD = "STRU"
	TransferMode       CMD = "MODE"

	// FTP Service Commands
	Retrieve              CMD = "RETR"
	Store                 CMD = "STOR"
	StoreUnique           CMD = "STOU"
	Append                CMD = "APPE"
	Allocate              CMD = "ALLO"
	Restart               CMD = "REST"
	Renamefrom            CMD = "RNFR"
	Renameto              CMD = "RNTO"
	Abort                 CMD = "ABOR"
	Delete                CMD = "DELE"
	Removedirectory       CMD = "RMD"
	Makedirectory         CMD = "MKD"
	Printworkingdirectory CMD = "PWD"
	List                  CMD = "LIST"
	Namelist              CMD = "NLST"
	Siteparameters        CMD = "SITE"
	System                CMD = "SYST"
	Status                CMD = "STAT"
	Help                  CMD = "HELP"
	Noop                  CMD = "NOOP"
)

var CMDS = []CMD{
	// ACCESS CONTROL COMMANDS
	Username,
	Password,
	Account,
	ChangeWorkingDirectory,
	ChangeToParentDirectory,
	StructureMount,
	Reinitialize,
	Logout,

	// Transfer Parameter Commands
	DataPort,
	Passive,
	RepresentationType,
	FileStructure,
	TransferMode,

	// FTP Service Commands
	Retrieve,
	Store,
	StoreUnique,
	Append,
	Allocate,
	Restart,
	Renamefrom,
	Renameto,
	Abort,
	Delete,
	Removedirectory,
	Makedirectory,
	Printworkingdirectory,
	List,
	Namelist,
	Siteparameters,
	System,
	Status,
	Help,
	Noop,
}

func CheckRequestCMD(b []byte) bool {
	for _, c := range CMDS {
		if CMD(string(b)) == c {
			return true
		}
	}
	return false
}
