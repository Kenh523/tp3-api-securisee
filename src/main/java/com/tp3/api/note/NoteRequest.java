package com.tp3.api.note;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** DTO d'entree : ni id ni owner -> pas de mass assignment. */
public record NoteRequest(
        @NotBlank @Size(max = 100) String title,
        @NotBlank @Size(max = 2000) String content) {
}
