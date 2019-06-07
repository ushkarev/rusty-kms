use crate::key_store::errors::*;
use crate::key_store::tag::Tag;
use crate::key_store::key::{Key, State};

impl Key {
    pub fn add_tag(&mut self, tag: Tag) -> Result<(), AddTagError> {
        if let State::PendingDeletion(_) = self.state {
            return Err(AddTagError::InvalidState);
        }
        if let Some(existing_tag) = self.tags.iter_mut().find(|t| t.key() == tag.key()) {
            *existing_tag = tag;
        } else {
            self.tags.push(tag);
        }
        Ok(())
    }

    pub fn remove_tag(&mut self, tag_key: &str) -> Result<Tag, RemoveTagError> {
        if let State::PendingDeletion(_) = self.state {
            return Err(RemoveTagError::InvalidState);
        }
        // TODO: should removing a non-existant tag fail?
        self.tags.iter()
            .position(|t| t.key() == tag_key)
            .map(|index| self.tags.remove(index))
            .ok_or(RemoveTagError::NotFound)
    }
}
