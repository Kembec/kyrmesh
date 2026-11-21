package templates

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// The admin console is read on the administrator's phone between other
// things: the invitation just made sits on top with the two ways to send
// it, and every page carries a data-kyrmesh marker so tests assert the
// state, not the wording (KEM-464).

const adminLang = "es"

// Why the console refused, also the data-kyrmesh marker of the page.
const (
	AdminNoSession   = "admin-no-session"
	AdminLinkInvalid = "admin-link-invalid"
	AdminBadForm     = "admin-bad-form"
	AdminSignedOut   = "admin-signed-out"
	AdminFailed      = "admin-failed"
)

// Notices shown above the console after a form that could not be applied.
const (
	AdminNoticeBadUser   = "notice-bad-user"
	AdminNoticeBadExpiry = "notice-bad-expiry"
	AdminNoticeGone      = "notice-gone"
)

// AdminChoice is one option of a select.
type AdminChoice struct {
	Value string
	Label string
}

// AdminShareInfo is an invitation that can still be sent.
type AdminShareInfo struct {
	Link    string
	Owner   string
	Expires time.Time
}

// AdminPendingInfo is an invitation nobody has used yet.
type AdminPendingInfo struct {
	Owner        string
	Expires      *time.Time
	RevokeAction string
}

// AdminPageInfo is everything the console shows.
type AdminPageInfo struct {
	CSRFField    string
	CSRFToken    string
	CreateAction string
	LogoutAction string
	Notice       string
	Share        *AdminShareInfo
	Users        []AdminChoice
	Expiries     []AdminChoice
	Pending      []AdminPendingInfo
}

var adminNotices = map[string]string{
	AdminNoticeBadUser:   "Elige para quién es la invitación.",
	AdminNoticeBadExpiry: "Elige cuándo vence la invitación.",
	AdminNoticeGone:      "Esa invitación ya no estaba pendiente: se usó, venció o ya la revocaste.",
}

// AdminPage renders the console: the invitation to send, a new one, and the
// pending ones with a way to revoke each.
func AdminPage(info AdminPageInfo) *elem.Element {
	children := []elem.Node{H2(elem.Text("Invitaciones"))}

	if text, ok := adminNotices[info.Notice]; ok {
		children = append(children, elem.Div(attrs.Props{"data-kyrmesh": info.Notice},
			errorBox("No se aplicó", elem.Text(text))))
	}

	if info.Share != nil {
		children = append(children, adminShare(*info.Share))
	}

	children = append(children,
		adminCreateForm(info),
		adminPendingList(info),
		adminForm(info.LogoutAction, info, nil, adminQuietButton("Cerrar sesión")),
	)

	return adminLayout("Invitaciones", "admin-console", children...)
}

func adminShare(share AdminShareInfo) *elem.Element {
	message := "Te invito a mi red privada. Abre este enlace en el teléfono o la computadora que quieres conectar:\n" +
		share.Link + "\nSirve para un solo dispositivo y vence en " + UntilText(share.Expires) + "."

	return elem.Div(attrs.Props{"data-kyrmesh": "admin-share"},
		successBox("Invitación lista para "+share.Owner,
			elem.Text("Envíala a la persona; sirve para un solo dispositivo y vence en "+UntilText(share.Expires)+"."),
		),
		elem.Input(attrs.Props{
			attrs.Type:      "text",
			attrs.Readonly:  "true",
			attrs.Value:     share.Link,
			attrs.Name:      "link",
			attrs.AriaLabel: "Enlace de la invitación",
			attrs.Style:     adminFieldStyle(),
		}),
		elem.Div(attrs.Props{attrs.Style: styles.Props{
			styles.Display:   "flex",
			styles.FlexWrap:  "wrap",
			styles.Gap:       spaceS,
			styles.MarginTop: spaceM,
		}.ToInline()},
			adminLinkButton("https://wa.me/?text="+mailEscape(message), "Enviar por WhatsApp", "share-whatsapp"),
			adminLinkButton("mailto:?subject="+mailEscape("Tu invitación a la red privada")+"&body="+mailEscape(message),
				"Enviar por correo", "share-email"),
		),
	)
}

func adminCreateForm(info AdminPageInfo) *elem.Element {
	if len(info.Users) == 0 {
		return elem.Div(nil,
			H3(elem.Text("Nueva invitación")),
			P(elem.Text("Aún no hay usuarios en la red. Crea el primero en el servidor con "),
				Code(elem.Text("kyr users create <nombre>")), elem.Text(" y vuelve a esta página.")),
		)
	}

	return elem.Div(nil,
		H3(elem.Text("Nueva invitación")),
		adminForm(info.CreateAction, info, attrs.Props{"data-kyrmesh": "admin-create"},
			adminSelect("user", "¿Para quién?", info.Users),
			adminSelect("expires", "Vence en", info.Expiries),
			elem.Button(attrs.Props{attrs.Type: "submit"}, elem.Text("Crear invitación")),
		),
	)
}

func adminPendingList(info AdminPageInfo) *elem.Element {
	title := H3(elem.Text("Pendientes (" + strconv.Itoa(len(info.Pending)) + ")"))
	if len(info.Pending) == 0 {
		return elem.Div(nil, title, P(elem.Text("No hay invitaciones sin usar.")))
	}

	items := make([]elem.Node, 0, len(info.Pending))
	for _, p := range info.Pending {
		expires := "no vence"
		if p.Expires != nil {
			expires = "vence en " + UntilText(*p.Expires)
		}

		items = append(items, elem.Li(attrs.Props{
			"data-kyrmesh": "admin-pending",
			attrs.Style: styles.Props{
				styles.Display:        "flex",
				styles.AlignItems:     cssCenter,
				styles.JustifyContent: "space-between",
				styles.Gap:            spaceM,
				styles.Padding:        spaceS + " 0",
				styles.BorderBottom:   cssBorderHS,
			}.ToInline(),
		},
			elem.Span(nil, elem.Strong(nil, elem.Text(p.Owner)), elem.Text(" · "+expires)),
			adminForm(p.RevokeAction, info, nil, adminQuietButton("Revocar")),
		))
	}

	return elem.Div(nil, title, elem.Ul(attrs.Props{attrs.Style: styles.Props{
		styles.ListStyleType: "none",
		styles.Padding:       "0",
		styles.Margin:        "0",
	}.ToInline()}, items...))
}

// adminDenials maps each refusal to what the person sees and what to do.
var adminDenials = map[string][2]string{
	AdminNoSession: {"Necesitas un enlace de administrador",
		"En el servidor, ejecuta «kyr admin link» y abre el enlace en este navegador. Cada enlace sirve una sola vez y vence en 10 minutos."},
	AdminLinkInvalid: {"Este enlace de administrador ya no sirve",
		"Ya se usó o venció: cada enlace abre una sola sesión. Pide otro con «kyr admin link»."},
	AdminBadForm: {"No pudimos confirmar el formulario",
		"Vuelve a la página de invitaciones y repite la acción."},
	AdminFailed: {"Algo falló en el servidor",
		"Vuelve a intentarlo en unos minutos."},
}

// AdminDenied renders a refusal, or the page after signing out.
func AdminDenied(reason string) *elem.Element {
	if reason == AdminSignedOut {
		return adminLayout("Sesión cerrada", reason,
			successBox("Sesión cerrada", elem.Text("Para volver, pide otro enlace con «kyr admin link».")))
	}

	text, ok := adminDenials[reason]
	if !ok {
		reason, text = AdminFailed, adminDenials[AdminFailed]
	}

	return adminLayout(text[0], reason, errorBox(text[0], elem.Text(text[1])))
}

func adminLayout(title, marker string, children ...elem.Node) *elem.Element {
	head := elem.Fragment(elem.Title(nil, elem.Text("Kyrmesh - "+title)))
	body := mdTypesetBody(headscaleLogo(), elem.Div(attrs.Props{"data-kyrmesh": marker}, children...), pageFooter())

	return HtmlStructureLang(adminLang, head, body)
}

// adminForm is a POST form that carries the session's token.
func adminForm(action string, info AdminPageInfo, props attrs.Props, children ...elem.Node) *elem.Element {
	if props == nil {
		props = attrs.Props{}
	}

	props[attrs.Method] = "POST"
	props[attrs.Action] = action
	props[attrs.Style] = styles.Props{styles.Margin: "0"}.ToInline()

	hidden := elem.Input(attrs.Props{attrs.Type: "hidden", attrs.Name: info.CSRFField, attrs.Value: info.CSRFToken})

	return elem.Form(props, append([]elem.Node{hidden}, children...)...)
}

func adminSelect(name, label string, choices []AdminChoice) *elem.Element {
	options := make([]elem.Node, 0, len(choices))
	for _, c := range choices {
		options = append(options, elem.Option(attrs.Props{attrs.Value: c.Value}, elem.Text(c.Label)))
	}

	return elem.Label(attrs.Props{attrs.Style: styles.Props{
		styles.Display:      "block",
		styles.MarginBottom: spaceM,
	}.ToInline()},
		elem.Text(label),
		elem.Select(attrs.Props{attrs.Name: name, attrs.Style: adminFieldStyle()}, options...),
	)
}

func adminFieldStyle() string {
	return styles.Props{
		styles.Display:         "block",
		styles.Width:           "100%",
		styles.BoxSizing:       "border-box",
		styles.MarginTop:       spaceXS,
		styles.Padding:         "0.625rem 0.75rem",
		styles.FontSize:        "1rem",
		styles.Color:           "inherit",
		styles.BackgroundColor: "transparent",
		styles.Border:          cssBorderHS,
		styles.BorderRadius:    "0.375rem",
		"min-height":           "44px",
	}.ToInline()
}

// adminLinkButton opens another app (WhatsApp, the mail client) with the
// message already written.
func adminLinkButton(href, text, marker string) *elem.Element {
	return elem.A(attrs.Props{
		attrs.Href:     href,
		attrs.Rel:      "noreferrer noopener",
		attrs.Target:   "_blank",
		"data-kyrmesh": marker,
		attrs.Style: styles.Props{
			styles.Display:         "inline-flex",
			styles.AlignItems:      cssCenter,
			styles.Padding:         "0.75rem 1.5rem",
			styles.BackgroundColor: "var(--md-primary-fg-color)",
			styles.Color:           "#ffffff",
			styles.TextDecoration:  "none",
			styles.BorderRadius:    "0.375rem",
			styles.FontWeight:      "500",
			"min-height":           "44px",
		}.ToInline(),
	}, elem.Text(text))
}

// adminQuietButton is a secondary action: outlined, so it never competes
// with "Crear invitación".
func adminQuietButton(text string) *elem.Element {
	return elem.Button(attrs.Props{
		attrs.Type: "submit",
		attrs.Style: styles.Props{
			styles.Color:           "var(--md-primary-fg-color)",
			styles.BackgroundColor: "transparent",
			styles.Border:          "1px solid var(--md-primary-fg-color)",
			styles.Padding:         "0.5rem 1rem",
		}.ToInline(),
	}, elem.Text(text))
}

// mailEscape percent-encodes for mailto: and wa.me, where "+" would show as
// a literal plus instead of a space.
func mailEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// UntilText says how long until t, rounded the way a person says it:
// "45 minutos", "24 horas", "7 días".
func UntilText(t time.Time) string {
	d := time.Until(t)
	if d < time.Minute {
		return "menos de un minuto"
	}

	if m := int(d.Round(time.Minute).Minutes()); m < 60 {
		return plural(m, "minuto", "minutos")
	}

	if h := int(d.Round(time.Hour).Hours()); h < 36 {
		return plural(h, "hora", "horas")
	}

	return plural(int((d+12*time.Hour)/(24*time.Hour)), "día", "días")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}

	return strconv.Itoa(n) + " " + many
}
