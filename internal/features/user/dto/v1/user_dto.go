package v1

import (
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/pagination"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/features/user/domain"
)

// CreateUserRequest is the request body for POST /users.
type CreateUserRequest struct {
	FirstName   string  `json:"first_name" binding:"required,min=2,max=50"`
	LastName    string  `json:"last_name" binding:"required,min=2,max=50"`
	Email       string  `json:"email" binding:"required,email,email_advanced"`
	Password    string  `json:"password" binding:"required,min=8,max=72,password_strong"`
	PhoneNumber *string `json:"phone_number" binding:"omitempty,phone_advanced"`
}

// ToCreateUserInput converts CreateUserRequest to domain input.
func ToCreateUserInput(req CreateUserRequest) domain.CreateUserInput {
	return domain.CreateUserInput{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		Email:       req.Email,
		Password:    req.Password,
		PhoneNumber: req.PhoneNumber,
	}
}

// UpdateUserRequest is the request body for PATCH /users/:uuid; "phone_number": "" clears the phone.
type UpdateUserRequest struct {
	FirstName   *string `json:"first_name" binding:"omitempty,min=2,max=50"`
	LastName    *string `json:"last_name" binding:"omitempty,min=2,max=50"`
	PhoneNumber *string `json:"phone_number" binding:"omitzero,phone_advanced"`
	Status      *string `json:"status" binding:"omitempty,oneof=active inactive"`
}

// ToUpdateUserInput converts UpdateUserRequest to domain input.
func ToUpdateUserInput(req UpdateUserRequest) domain.UpdateUserInput {
	var status *int16
	if req.Status != nil {
		// The binding tag guarantees a known name.
		if s, ok := domain.ParseUserStatus(*req.Status); ok {
			status = &s
		}
	}

	return domain.UpdateUserInput{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		PhoneNumber: req.PhoneNumber,
		Status:      status,
	}
}

// ListUsersRequest binds query parameters for listing users.
type ListUsersRequest struct {
	pagination.Request
}

// ToFilter converts ListUsersRequest to domain filter.
func (r *ListUsersRequest) ToFilter() domain.UserListFilter {
	return domain.UserListFilter{
		Search:    r.Search,
		Limit:     r.GetLimit(),
		Offset:    r.GetOffset(),
		SortOrder: r.SortOrder,
	}
}

// UserResponse represents the JSON response for a user.
type UserResponse struct {
	UUID        uuid.UUID  `json:"uuid"`
	Email       string     `json:"email"`
	FirstName   string     `json:"first_name"`
	LastName    string     `json:"last_name"`
	PhoneNumber *string    `json:"phone_number,omitempty"`
	AvatarURL   *string    `json:"avatar_url,omitempty"`
	Status      string     `json:"status"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// NewUserResponse converts domain.User to UserResponse.
func NewUserResponse(u *domain.User) UserResponse {
	return UserResponse{
		UUID:        u.UUID,
		Email:       u.Email,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		PhoneNumber: u.PhoneNumber,
		AvatarURL:   u.AvatarURL,
		Status:      domain.UserStatusName(u.Status),
		Active:      u.IsActive(),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// NewUserResponseList converts a slice of domain.User to UserResponse list.
func NewUserResponseList(users []*domain.User) []UserResponse {
	return slicex.Map(users, NewUserResponse)
}
