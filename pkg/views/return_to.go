package views

// ReturnToField names the page a signed-out visitor asked for, carried through
// sign-in (login, then MFA when it applies) so they land back on it. The login
// and MFA forms hold it in a hidden input; the redirects to those pages carry
// it as a query parameter of this name. The handlers accept only a path on
// identity itself (httpserver.safeReturnPath); anything else is dropped.
const ReturnToField = "return_to"
