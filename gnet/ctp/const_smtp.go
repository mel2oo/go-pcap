package ctp

// SMTP COMMANDS
const (
	SmtpEhlo CMD = "EHLO"
	SmtpMail CMD = "MAIL"
	SmtpRcpt CMD = "RCPT"
	SmtpSize CMD = "SIZE"
	SmtpData CMD = "DATA"
	SmtpVrfy CMD = "VRFY"
	SmtpTurn CMD = "TURN"
	SmtpAuth CMD = "AUTH"
	SmtpRset CMD = "RSET"
	SmtpExpn CMD = "EXPN"
	SmtpHelp CMD = "HELP"
	SmtpQuit CMD = "QUIT"
)

var SmtpCMDS = []CMD{
	SmtpEhlo,
	SmtpMail,
	SmtpRcpt,
	SmtpSize,
	SmtpData,
	SmtpVrfy,
	SmtpTurn,
	SmtpAuth,
	SmtpRset,
	SmtpExpn,
	SmtpHelp,
	SmtpQuit,
}

func CheckSmtpCMD(b []byte) bool {
	for _, c := range SmtpCMDS {
		if CMD(string(b)) == c {
			return true
		}
	}
	return false
}
