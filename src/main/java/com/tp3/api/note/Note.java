package com.tp3.api.note;

/** Entite interne : n'est JAMAIS exposee directement par l'API (cf. NoteResponse). */
public record Note(Long id, String title, String content, String owner) {
}
