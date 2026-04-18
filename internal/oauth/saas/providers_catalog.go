package saas

// Providers below are templates — everything except ClientID is fixed by
// the upstream vendor. Operators register their own OAuth app in each
// tenant and plug the ClientID into telepath config; the package keeps
// the URL + scope trivia so operators don't hand-type them.

// M365 is the Microsoft identity platform / Azure AD v2 endpoint.
// Scopes cover read-only Graph API access an operator typically wants for
// an AI-opportunity assessment: email, OneDrive files, SharePoint sites.
// `offline_access` is what gets you a refresh_token.
var M365 = Provider{
	Name:         "m365",
	AuthorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
	TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	RedirectURI:  "http://localhost:0/callback",
	Scopes: []string{
		"offline_access",
		"User.Read",
		"Mail.Read",
		"Files.Read.All",
		"Sites.Read.All",
	},
}

// Google Workspace / Google Cloud OAuth 2.0. access_type=offline is what
// gets you a refresh_token; prompt=consent forces the consent screen
// (matters on re-grants — otherwise Google silently skips refresh_token
// issuance on second authorization).
var Google = Provider{
	Name:         "google",
	AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
	TokenURL:     "https://oauth2.googleapis.com/token",
	RedirectURI:  "http://localhost:0/callback",
	Scopes: []string{
		"https://www.googleapis.com/auth/drive.readonly",
		"https://www.googleapis.com/auth/gmail.readonly",
		"https://www.googleapis.com/auth/userinfo.email",
	},
	ExtraAuthParams: map[string]string{
		"access_type": "offline",
		"prompt":      "consent",
	},
}

// Salesforce production login endpoint. Sandbox orgs use test.salesforce.com;
// operators who need that override AuthorizeURL/TokenURL on a copy of the
// struct. Scopes are the minimum for SOQL queries + refresh.
var Salesforce = Provider{
	Name:         "salesforce",
	AuthorizeURL: "https://login.salesforce.com/services/oauth2/authorize",
	TokenURL:     "https://login.salesforce.com/services/oauth2/token",
	RedirectURI:  "http://localhost:0/callback",
	Scopes: []string{
		"api",
		"refresh_token",
	},
}
