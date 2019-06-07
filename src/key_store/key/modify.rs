use chrono::{DateTime, Utc};

use crate::misc::days_from_now;
use crate::key_store::errors::*;
use crate::key_store::key::{Key, State, Kind};

impl Key {
    pub fn set_description<T>(&mut self, description: T) -> Result<(), SetDescriptionError> where T: Into<String> {
        if let State::PendingDeletion(_) = self.state {
            Err(SetDescriptionError::InvalidState)
        } else {
            self.description = description.into();
            Ok(())
        }
    }

    pub fn schedule_deletion(&mut self, days: usize) -> Result<&DateTime<Utc>, ScheduleDeletionError> {
        if days < 7 || days > 30 {
            Err(ScheduleDeletionError::DeletionWindow)
        } else if let State::PendingDeletion(_) = self.state {
            Err(ScheduleDeletionError::InvalidState)
        } else {
            self.state = State::PendingDeletion(days_from_now(days as i64));
            if let State::PendingDeletion(ref expires) = self.state {
                Ok(expires)
            } else {
                unreachable!();
            }
        }
    }

    pub fn cancel_deletion(&mut self) -> Result<(), CancelDeletionError> {
        if let State::PendingDeletion(_) = self.state {
            self.state = if self.is_external() && self.key_materials.is_empty() {
                State::PendingImport
            } else {
                State::Disabled
            };
            Ok(())
        } else {
            Err(CancelDeletionError::InvalidState)
        }
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), SetEnabledError> {
        match self.state {
            State::Enabled | State::Disabled => {
                self.state = if enabled { State::Enabled } else { State::Disabled };
                Ok(())
            },
            _ => Err(SetEnabledError::InvalidState),
        }
    }

    pub fn enable(&mut self) -> Result<(), SetEnabledError> {
        self.set_enabled(true)
    }

    pub fn disable(&mut self) -> Result<(), SetEnabledError> {
        self.set_enabled(false)
    }

    fn set_rotation(&mut self, rotates: bool) -> Result<(), SetRotationError> {
        if let State::Enabled = self.state {
            if self.is_external() {
                Err(SetRotationError::InvalidState)
            } else {
                self.kind = if rotates {
                    Kind::InternalRotates(days_from_now(365))
                } else {
                    Kind::Internal
                };
                Ok(())
            }
        } else {
            Err(SetRotationError::Disabled)
        }
    }

    pub fn enable_rotation(&mut self) -> Result<(), SetRotationError> {
        self.set_rotation(true)
    }

    pub fn disable_rotation(&mut self) -> Result<(), SetRotationError> {
        self.set_rotation(false)
    }

    pub fn remove_key_material(&mut self) -> Result<(), RemoveKeyMaterialError> {
        match self.state {
            State::Enabled | State::Disabled => {
                if self.is_external() {
                    self.force_remove_key_material();
                    Ok(())
                } else {
                    Err(RemoveKeyMaterialError::InternalKey)
                }
            },
            State::PendingImport => Ok(()),
            State::PendingDeletion(_) => Err(RemoveKeyMaterialError::PendingDeletion),
        }
    }
}
