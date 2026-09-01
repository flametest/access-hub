package domain

// Social provider ids (identities.provider, design.md §12 M5). A provider is
// enabled when its credentials are configured in server-config.yaml
// (Social.*: clientId/clientSecret, apple servicesId/teamId/keyId/privateKeyPath).
const (
	SocialProviderGoogle    = "google"
	SocialProviderMicrosoft = "microsoft"
	SocialProviderFacebook  = "facebook"
	SocialProviderApple     = "apple"
)

// SocialProviderLabels maps provider ids to their display labels
// (GET /api/v1/me/signin-methods entries).
var SocialProviderLabels = map[string]string{
	SocialProviderGoogle:    "Google",
	SocialProviderMicrosoft: "Microsoft",
	SocialProviderFacebook:  "Facebook",
	SocialProviderApple:     "Apple",
}
