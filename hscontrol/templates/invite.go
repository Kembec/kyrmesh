package templates

import (
	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// The invitation pages are read by someone who has never configured a
// network: they say what to tap, in the person's language, and every page
// carries a data-kyrmesh marker so tests assert the state, not the wording.

// Invitation problems, also used as the data-kyrmesh marker of the page.
const (
	InviteInvalid        = "invite-invalid"
	InviteExpired        = "invite-expired"
	InviteUsed           = "invite-used"
	InviteMissing        = "invite-missing"
	InviteRequestExpired = "request-expired"
	InviteNotConfirmed   = "not-confirmed"
	InviteDeviceUnknown  = "device-unknown"
	InviteFailed         = "invite-failed"
)

const inviteLang = "es"

// InviteStepsInfo is what the landing page of a valid invitation shows.
type InviteStepsInfo struct {
	// User is who the device will belong to.
	User string
	// Expires is the invitation's expiry, already formatted for people.
	Expires string
	// ServerURL is the address the app must point at.
	ServerURL string
}

// InviteSteps renders the three steps that take a person from the
// invitation link to the confirmation page, with no command to run.
func InviteSteps(info InviteStepsInfo) *elem.Element {
	return invitePage("Conecta tu dispositivo", "invite-steps",
		H2(elem.Text("Conecta tu dispositivo")),
		P(
			elem.Text("Te invitaron a una red privada como "),
			elem.Strong(nil, elem.Text(info.User)),
			elem.Text(". La invitación sirve para un solo dispositivo"+info.Expires+"."),
		),
		elem.Ol(nil,
			inviteStep("Instala la app Tailscale.",
				externalLink("https://apps.apple.com/app/tailscale/id1470499037", "iPhone, iPad y Mac"),
				elem.Text(" · "),
				externalLink("https://play.google.com/store/apps/details?id=com.tailscale.ipn", "Android"),
			),
			inviteStep("Indícale a la app que use esta red.",
				elem.Text("En iPhone o iPad, descarga "),
				elem.A(attrs.Props{attrs.Href: "/apple/ios"}, elem.Text("el perfil para iPhone")),
				elem.Text(", abre Ajustes y toca «Perfil descargado» e «Instalar». En Mac, descarga "),
				elem.A(attrs.Props{attrs.Href: "/apple/macos-app-store"}, elem.Text("el perfil para Mac")),
				elem.Text(" y apruébalo en Ajustes del Sistema. En Android, abre la app, toca tu cuenta, "+
					"luego «⋮» › «Usar otro servidor» («Use an alternate server») y pega esta dirección: "),
				Code(elem.Text(info.ServerURL)),
			),
			inviteStep("Abre la app y toca «Iniciar sesión» («Log in» si está en inglés).",
				elem.Text("Se abrirá una página para que confirmes que este dispositivo es tuyo."),
			),
		),
		P(elem.Text("Haz estos pasos en el dispositivo que quieres conectar. Si abriste el enlace dentro de WhatsApp "+
			"o del correo, ábrelo en Safari o Chrome: la invitación se guarda en el navegador.")),
	)
}

// InviteConfirmInfo is what the confirmation page shows before the device
// is registered.
type InviteConfirmInfo struct {
	FormAction    string
	CSRFTokenName string
	CSRFToken     string
	User          string
	Hostname      string
	OS            string
}

// InviteConfirm asks the person to confirm that the device the app is
// registering is theirs. Registration happens only on the POST, so opening
// the page never registers anything by itself.
func InviteConfirm(info InviteConfirmInfo) *elem.Element {
	return invitePage("Confirma tu dispositivo", "invite-confirm",
		H2(elem.Text("¿Conectar este dispositivo?")),
		deviceTable([4][2]string{
			{"Dispositivo", info.Hostname},
			{"Sistema", inviteOrUnknown(info.OS)},
			{"Se conecta como", info.User},
			{"Acceso", "Solo lo que tu invitación permite"},
		}),
		elem.Form(
			attrs.Props{attrs.Method: "POST", attrs.Action: info.FormAction},
			elem.Input(attrs.Props{
				attrs.Type:  "hidden",
				attrs.Name:  info.CSRFTokenName,
				attrs.Value: info.CSRFToken,
			}),
			elem.Button(attrs.Props{attrs.Type: "submit"}, elem.Text("Conectar este dispositivo")),
		),
		P(elem.Text("Si no reconoces este dispositivo, cierra esta página: no se conectará nada.")),
	)
}

// InviteStatusInfo describes the device an invitation just registered.
type InviteStatusInfo struct {
	User     string
	Hostname string
	Online   bool
	// RefreshURL reloads the page while the device is not yet online.
	RefreshURL string
}

// InviteStatus says whether the registered device is already connected,
// and while it is not, reloads itself every few seconds.
func InviteStatus(info InviteStatusInfo) *elem.Element {
	if info.Online {
		return invitePage("Conectado", "connected",
			successBox("Conectado",
				elem.Text(info.Hostname+" ya está en la red privada como "),
				elem.Strong(nil, elem.Text(info.User)),
				elem.Text(". Puedes cerrar esta página."),
			),
		)
	}

	return invitePageHead("Casi listo", "waiting",
		elem.Meta(attrs.Props{attrs.HTTPequiv: "refresh", attrs.Content: "3;url=" + info.RefreshURL}),
		warningBox("Falta abrir la app",
			info.Hostname+" ya quedó aceptado como "+info.User+
				". Vuelve a la app Tailscale: en unos segundos debería decir «Conectado» («Connected» en inglés). "+
				"Esta página se actualiza sola."),
	)
}

// inviteProblems maps each problem to what the person sees and what to do.
var inviteProblems = map[string][2]string{
	InviteInvalid: {"Esta invitación no es válida",
		"Puede que el enlace esté incompleto. Ábrelo de nuevo desde el mensaje o pide uno nuevo a quien te invitó."},
	InviteExpired: {"Esta invitación venció o fue anulada",
		"Pide una nueva a quien te invitó."},
	InviteUsed: {"Esta invitación ya se usó",
		"Cada invitación conecta un solo dispositivo. Para conectar otro, pide una nueva a quien te invitó."},
	InviteMissing: {"Primero abre tu invitación",
		"Este navegador no tiene tu invitación. Abre aquí el enlace que te enviaron y vuelve a la app a tocar «Iniciar sesión»."},
	InviteRequestExpired: {"Se acabó el tiempo para conectar",
		"Vuelve a la app y toca «Iniciar sesión» otra vez."},
	InviteNotConfirmed: {"No pudimos confirmar tu dispositivo",
		"Vuelve a la app y toca «Iniciar sesión» otra vez."},
	InviteDeviceUnknown: {"No encontramos ese dispositivo",
		"Vuelve a la app: si dice «Conectado», ya está listo. Si no, toca «Iniciar sesión» otra vez."},
	InviteFailed: {"No se pudo conectar el dispositivo",
		"En unos minutos, vuelve a la app y toca «Iniciar sesión». Si sigue fallando, avisa a quien te invitó."},
}

// InviteError renders the page for an invitation problem; unknown problems
// fall back to the generic failure.
func InviteError(problem string) *elem.Element {
	text, ok := inviteProblems[problem]
	if !ok {
		problem, text = InviteFailed, inviteProblems[InviteFailed]
	}

	return invitePage(text[0], problem, errorBox(text[0], elem.Text(text[1])))
}

func invitePage(title, marker string, children ...elem.Node) *elem.Element {
	return invitePageHead(title, marker, nil, children...)
}

func invitePageHead(title, marker string, extraHead elem.Node, children ...elem.Node) *elem.Element {
	head := []elem.Node{elem.Title(nil, elem.Text("Kyrmesh - "+title))}
	if extraHead != nil {
		head = append(head, extraHead)
	}

	body := append([]elem.Node{
		headscaleLogo(),
		elem.Div(attrs.Props{"data-kyrmesh": marker}, children...),
	}, pageFooter())

	return HtmlStructureLang(inviteLang, elem.Fragment(head...), mdTypesetBody(body...))
}

func inviteStep(title string, detail ...elem.Node) *elem.Element {
	return elem.Li(attrs.Props{
		attrs.Style: styles.Props{
			styles.MarginBottom: spaceM,
			styles.LineHeight:   lineHeightBase,
		}.ToInline(),
	}, append([]elem.Node{elem.Strong(nil, elem.Text(title)), elem.Br(nil)}, detail...)...)
}

func inviteOrUnknown(s string) string {
	if s == "" {
		return "(desconocido)"
	}

	return s
}
