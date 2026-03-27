//! Shared library for RLN guest programs.
//!
//! This module provides common functionality used across guest programs,
//! including an abstracted hashing interface, merkle tree operations,
//! and registration logic.

pub mod hash;
pub mod layouts;
pub mod merkle_tree;
pub mod registration;
