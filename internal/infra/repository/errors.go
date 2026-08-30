package repository

import (
	"errors"
	"fmt"

	"github.com/flametest/vita/verrors"
	"gorm.io/gorm"
)

// translateFirst maps gorm's ErrRecordNotFound to verrors.NotFoundError so the
// API layer can rely on verrors error codes exclusively.
func translateFirst(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return verrors.NotFoundError(fmt.Sprintf(format, args...))
	}
	return err
}

// updateRowsAffected finalizes an id-targeted update. The optimistic-lock
// plugin reports a 0-row update as ErrOptimisticLock; for id-targeted updates
// that can only mean "row absent (or soft-deleted)", which we surface as
// NotFoundError.
func updateRowsAffected(res *gorm.DB, notFoundMsg string) error {
	if res.Error != nil && !errors.Is(res.Error, verrors.ErrOptimisticLock) {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return verrors.NotFoundError(notFoundMsg)
	}
	return nil
}

// IsNotFound reports whether err is a repository not-found error. Useful for
// services implementing "find-or-create" flows (e.g. bootstrap, auto-provision).
func IsNotFound(err error) bool {
	var e *verrors.Error
	if verrors.As(err, &e) {
		return e.ErrCode() == verrors.NotFoundCode
	}
	return false
}
