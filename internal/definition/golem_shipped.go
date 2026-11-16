package definition

// Every version of a skill Golem has shipped, by definition hash: the hash Build
// gives a skill directory holding one SKILL.md with that text. A skill Golem's
// agent installs is Golem's own text, so a new release of it is not an asset
// changing what it tells the agent behind an admin's back; without this list
// every release raised definition drift against Golem's own skills.
//
// Only an exact match counts: an edited copy of a Golem skill hashes to
// something else and drifts like any other skill. The list is append-only, so a
// machine still on an older release is recognised too. A skill's text changing
// fails witness's TestEveryShippedGolemSkillIsListed until its hash is added.
var golemSkillVersions = map[string]string{
	"ba483c58e9fb95f943d11134f60a5286d43ae60670c6e70ef96796e02df8e60e": "contained 2026-09-24",
	"bc3f9ed0e1e7bbd59a6aa23c7e8dddaa542bf2f56e2393da65e651002ea3bf7d": "golem-contained 2026-09-23",
	"52691a676b8b0327c594636c09d2934fc5ae073776cc34af321b06bcc62ea70f": "golem-contained 2026-09-24",
	"8334921cf02ce0e306a0bc4bdd511e1c9909a682c887a7f46d5c792fa72046ab": "golem-contained 2026-09-24",
	"491cf4285bb8f716db8236b6b153b156e95316b6a097d02a3dd09113ad97e559": "golem-contained 2026-09-24",
	"509610a6b65b2a256fb06cecda2d3c13316f6158a7e287d4949000415015fe73": "golem-contained 2026-09-24",
	"df8d5b616d342f343232b9054f89969e071b26631d3309066ab5d2f0bc6e7900": "golem-contained 2026-09-24",
	"e59e47fe11eaa506c14e26bc797664c963d7152fd8294b14260a7936c6fbd6d7": "golem-contained 2026-09-24",
	"600b4cee6b6db1be507ffc7647af0f51f31d7d9301a3c56585cc094e41cc41b3": "golem-contained 2026-09-29",
	"d2d06a64f6a1d7dfaca2e5f0ef2df0384046fd1bccd6d74431a735c55c80a446": "golem-fleet 2026-08-26",
	"2bd097e1b4c52a10bec5085aabda3c85840cd1a44927706c79184ddf33c9b5b5": "golem-fleet 2026-10-01",
	"939c6fbee2287d1bd612900649f536402ceeb0f5f92bf5c6bd775172675d14fe": "golem-fleet 2026-10-02",
	"8acb2444e07fcb4900eec9d57e9023e0655595a8f2fa0a73ebf73f03fe415063": "golem-fleet 2026-10-02",
	"f575dd7ee5990fe5c17cb8feea1ef42ea8b0a3a3103588285b32dfa623198b75": "golem-fleet 2026-10-02",
	"e32f99a406ceeb8122279ccdd5309cdcea1994474b95502750991aa276c58932": "golem-fleet 2026-10-02",
	"ca390cc891cb0eb2bf5ada03e6226fe10fd6cd343b7e9bd0f0bcc73dffb3061d": "golem-fleet 2026-10-25",
	"8b8afdb5eea256a0615f18ae602cd71376eea7c6e8d5bff3fb39f348ff205bc4": "golem-fleet 2026-10-30",
	"de709a90dd83c5fd49e069f71e972fce0a8f9a71e19958925443dc2a1e627e66": "golem-fleet 2026-11-15",
	"5b59a46081fef49b3bff307b8d5a0334945fe85846f99cb0f16f2429f29bd17f": "golem-phishing 2026-10-20",
	"093afb0bb2c5fcae38ce15c4a06814e4d1d915f56c408aac10a08fd44c79ec92": "golem-phishing 2026-10-20",
	"913ec805075513f61ffe928eb7f53248d8ef0c39c0804307221edf84ae5f7f49": "golem-phishing 2026-10-20",
	"c2921641ece9c70576b3348e66d18148fb6ffaaec6be2c9fc70d0842977149cf": "golem-phishing 2026-10-21",
	"65137f7858b8e790ccb460bb3990b4b1895fcd96a70c9fe364b7affc87eda467": "golem-phishing 2026-10-21",
	"17fb31a2b351848fb9305687dec104078cc911edb654d864e6f2de3f233c2e25": "golem-phishing 2026-10-21",
	"184173fc75b6c20345f2ec9b87a113ac27834a0a3334e810866e33267a544379": "golem-phishing 2026-10-22",
	"a130b7bb6b29ebc97e542f017e2dbcb7c333566c955aa698bcb42cbf3572a1b5": "golem-phishing 2026-10-22",
	"b996594586289f86c8026a2e712842555a49c5dfbdfd8d86cfa2a54c84c3f907": "golem-phishing 2026-10-22",
	"1834f46b959367061e2aa2830da6e94e48e6be8cb4623b06d5090e70d0d3b9d3": "golem-phishing 2026-10-22",
	"f7ee3b9573be45e7459bd9b94a6a4638b406fb1717d16da7fb1b1284b7702023": "golem-phishing 2026-10-22",
	"0d0ca1b94caa42185ce331bc8b4ff98491a8b625b018dcf6f08b5b7e334de395": "golem-phishing 2026-10-24",
	"2d386a0009ef03ec83ddb5fb168474392ffb597f2eb91ddb18efa50564479ab7": "golem-sandbox 2026-09-29",
	"e6372c5279e7fd22e9996f06e1bc9726ad22221e872a766bdeea41bedf62cf6c": "golem-sandbox 2026-10-02",
	"63cad770fc8bb46ea8e8293aaffebe4905f7c3c043aaad8a524d7a435f891ad6": "golem-sandbox 2026-10-20",
	"beda19a288e81f0bdb6d11f8342c7aa5676ee29678bdf98e909517d12b2f05e0": "golem-sandbox 2026-10-20",
	"f2b1109285641c7ac3c076e4cb592d02ff4a1304cebd7fe1c74e9d86f4e80c80": "golem-sandbox 2026-10-21",
	"1f97ee179a1359787a08f08da4e701de77ef49dc400313f55ce46809ec07ad6d": "golem-sandbox 2026-10-21",
	"0ffe0edd4d55790bacd8746a50c71e99d4e314a1024dc0e78adaa03013d2f96e": "golem-sandbox 2026-10-21",
	"1323eff444a5f85e3ef15eaa42c51e49cec8d0523c1ecdb42d295284922c4b3b": "golem-sandbox 2026-10-30",
	"2454c6ab08b6721eaf409370848fe02065c60cd369bece6127e7c31f233c7b3a": "safely 2026-09-24",
	"0703b365f2b6a97e1ca23c88e85e0446e9a23a64e15c8608f07b5ac906568465": "safely 2026-10-30",
	"844d7d8701a4d30b58f108eca40139076078c9b7af5db9fd9bd7c8816d09439c": "sandbox 2026-09-29",
}

// GolemShippedSkill reports whether a skill's definition hash is one Golem shipped.
func GolemShippedSkill(hash string) bool {
	_, ok := golemSkillVersions[hash]
	return ok
}

// GolemShippedSkillHashes lists them, for a query that excludes them.
func GolemShippedSkillHashes() []string {
	out := make([]string, 0, len(golemSkillVersions))
	for h := range golemSkillVersions {
		out = append(out, h)
	}
	return out
}
