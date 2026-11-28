package v1

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/apidoc"
	"github.com/jun-develop/junkit/response"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
	v1dto "jungo/internal/features/user/dto/v1"
	v1handler "jungo/internal/features/user/handler/v1"
	"jungo/internal/middleware"
	"jungo/internal/router"
)

// UserRoutes registers the user feature's endpoints under a version group.
type UserRoutes struct {
	handler      *v1handler.UserHandler
	authenticate middleware.Authenticate
	guard        *middleware.Guard
}

// NewUserRoutes creates a UserRoutes.
func NewUserRoutes(handler *v1handler.UserHandler, authenticate middleware.Authenticate, guard *middleware.Guard) *UserRoutes {
	return &UserRoutes{handler: handler, authenticate: authenticate, guard: guard}
}

// Version implements router.Versioned; routes are nested under "/api/v1".
func (r *UserRoutes) Version() string {
	return "v1"
}

// Register implements router.Routes; every route requires a logged-in user. Authenticated routes
// act on a single user: the service allows the user themself, or a holder of the permission who
// also holds every permission of that user (UserService.authorize).
func (r *UserRoutes) Register(group *gin.RouterGroup) {
	users := group.Group("/users", gin.HandlerFunc(r.authenticate))

	users.POST("", r.guard.Can(r.handler.CreateUser, domain.UsersCreate))
	users.GET("", r.guard.Can(r.handler.ListUsers, domain.UsersRead))
	users.GET("/:uuid", r.guard.Authenticated(r.handler.GetUser))
	users.PATCH("/:uuid", r.guard.Authenticated(r.handler.UpdateUser))
	users.DELETE("/:uuid", r.guard.Can(r.handler.DeleteUser, domain.UsersDelete))
	users.POST("/:uuid/avatar", r.guard.Authenticated(r.handler.UploadAvatar))
	users.DELETE("/:uuid/avatar", r.guard.Authenticated(r.handler.DeleteAvatar))

	// The logged-in user's own profile; shares "/auth/me" with the auth feature's GET.
	me := group.Group("/auth/me", gin.HandlerFunc(r.authenticate))
	me.PATCH("", r.guard.Authenticated(r.handler.UpdateMe))
	me.POST("/avatar", r.guard.Authenticated(r.handler.UploadMyAvatar))
	me.DELETE("/avatar", r.guard.Authenticated(r.handler.DeleteMyAvatar))
}

// multipartOverhead is the room left in a body limit for multipart boundaries and part headers.
const multipartOverhead = 64 << 10

// BodyLimits implements router.BodyLimited; the avatar uploads are larger than SECURITY_MAX_BODY_SIZE.
func (r *UserRoutes) BodyLimits() []router.BodyLimit {
	const maxBytes = v1handler.MaxAvatarFileSize + multipartOverhead

	return []router.BodyLimit{
		{Method: http.MethodPost, Path: "/users/:uuid/avatar", MaxBytes: maxBytes},
		{Method: http.MethodPost, Path: "/auth/me/avatar", MaxBytes: maxBytes},
	}
}

// Docs implements router.Documented.
func (r *UserRoutes) Docs() []apidoc.Route {
	user := v1dto.UserResponse{}
	// manage are the errors of acting on a user: unknown or unseen, or stronger than the caller.
	manage := []*response.AppError{domain.ErrUserNotFound, actor.ErrForbidden, actor.ErrCannotManageStrongerUser}
	// self are the errors of acting on yourself: only your account deleted meanwhile.
	self := []*response.AppError{domain.ErrUserNotFound}

	return []apidoc.Route{
		{
			ID: "createUser", Method: http.MethodPost, Path: "/users", Summary: "Create a user",
			Body: v1dto.CreateUserRequest{}, Status: http.StatusCreated, Response: user,
			Errors: []*response.AppError{domain.ErrEmailAlreadyExists, domain.ErrPasswordTooLong},
		},
		{ID: "listUsers", Method: http.MethodGet, Path: "/users", Summary: "List users", Query: v1dto.ListUsersRequest{}, Response: user, Paginated: true},
		{
			ID: "getUser", Method: http.MethodGet, Path: "/users/:uuid", Summary: "Get a user", Description: "Yourself, or any user with users:read.",
			Response: user, Errors: []*response.AppError{domain.ErrUserNotFound},
		},
		{
			ID: "updateUser", Method: http.MethodPatch, Path: "/users/:uuid", Summary: "Update a user", Description: "Yourself, or any user with users:update.",
			Body: v1dto.UpdateUserRequest{}, Response: user, Errors: append(slices.Clone(manage), domain.ErrCannotChangeOwnStatus),
		},
		{
			ID: "deleteUser", Method: http.MethodDelete, Path: "/users/:uuid", Summary: "Delete a user",
			Errors: append(slices.Clone(manage), domain.ErrCannotDeleteSelf),
		},
		{
			ID: "uploadUserAvatar", Method: http.MethodPost, Path: "/users/:uuid/avatar", Summary: "Upload an avatar",
			Description: "JPEG, PNG or WebP, up to 5 MB.", Files: []string{"avatar"}, Response: user,
			Errors: append(slices.Clone(manage), domain.ErrInvalidAvatarFile),
		},
		{ID: "deleteUserAvatar", Method: http.MethodDelete, Path: "/users/:uuid/avatar", Summary: "Delete the avatar", Response: user, Errors: manage},
		{
			ID: "updateMe", Method: http.MethodPatch, Path: "/auth/me", Summary: "Update your profile",
			Description: "Needs no permission. Email, status and roles cannot be changed here.",
			Body:        v1dto.UpdateMeRequest{}, Response: user, Errors: self,
		},
		{
			ID: "uploadMyAvatar", Method: http.MethodPost, Path: "/auth/me/avatar", Summary: "Upload your avatar",
			Description: "Needs no permission. JPEG, PNG or WebP, up to 5 MB.", Files: []string{"avatar"}, Response: user,
			Errors: append(slices.Clone(self), domain.ErrInvalidAvatarFile),
		},
		{ID: "deleteMyAvatar", Method: http.MethodDelete, Path: "/auth/me/avatar", Summary: "Delete your avatar", Description: "Needs no permission.", Response: user, Errors: self},
	}
}
