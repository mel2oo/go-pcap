package ctp

type CMD string

// FTP COMMANDS
// https://www.w3.org/Protocols/rfc959/4_FileTransfer.html
const (
	// ACCESS CONTROL COMMANDS
	FtpUsername                CMD = "USER"
	FtpPassword                CMD = "PASS"
	FtpAccount                 CMD = "ACCT"
	FtpChangeWorkingDirectory  CMD = "CWD"
	FtpChangeToParentDirectory CMD = "CDUP"
	FtpStructureMount          CMD = "SMNT"
	FtpReinitialize            CMD = "REIN"
	FtpLogout                  CMD = "QUIT"

	// Transfer Parameter Commands
	FtpDataPort           CMD = "PORT"
	FtpPassive            CMD = "PASV"
	FtpRepresentationType CMD = "TYPE"
	FtpFileStructure      CMD = "STRU"
	FtpTransferMode       CMD = "MODE"

	// FTP Service Commands
	FtpRetrieve              CMD = "RETR"
	FtpStore                 CMD = "STOR"
	FtpStoreUnique           CMD = "STOU"
	FtpAppend                CMD = "APPE"
	FtpAllocate              CMD = "ALLO"
	FtpRestart               CMD = "REST"
	FtpRenamefrom            CMD = "RNFR"
	FtpRenameto              CMD = "RNTO"
	FtpAbort                 CMD = "ABOR"
	FtpDelete                CMD = "DELE"
	FtpRemovedirectory       CMD = "RMD"
	FtpMakedirectory         CMD = "MKD"
	FtpPrintworkingdirectory CMD = "PWD"
	FtpList                  CMD = "LIST"
	FtpNamelist              CMD = "NLST"
	FtpSiteparameters        CMD = "SITE"
	FtpSystem                CMD = "SYST"
	FtpStatus                CMD = "STAT"
	FtpHelp                  CMD = "HELP"
	FtpNoop                  CMD = "NOOP"
)

var FtpCMDS = []CMD{
	// ACCESS CONTROL COMMANDS
	FtpUsername,
	FtpPassword,
	FtpAccount,
	FtpChangeWorkingDirectory,
	FtpChangeToParentDirectory,
	FtpStructureMount,
	FtpReinitialize,
	FtpLogout,

	// Transfer Parameter Commands
	FtpDataPort,
	FtpPassive,
	FtpRepresentationType,
	FtpFileStructure,
	FtpTransferMode,

	// FTP Service Commands
	FtpRetrieve,
	FtpStore,
	FtpStoreUnique,
	FtpAppend,
	FtpAllocate,
	FtpRestart,
	FtpRenamefrom,
	FtpRenameto,
	FtpAbort,
	FtpDelete,
	FtpRemovedirectory,
	FtpMakedirectory,
	FtpPrintworkingdirectory,
	FtpList,
	FtpNamelist,
	FtpSiteparameters,
	FtpSystem,
	FtpStatus,
	FtpHelp,
	FtpNoop,
}

func CheckFtpCMD(b []byte) bool {
	for _, c := range FtpCMDS {
		if CMD(string(b)) == c {
			return true
		}
	}
	return false
}
