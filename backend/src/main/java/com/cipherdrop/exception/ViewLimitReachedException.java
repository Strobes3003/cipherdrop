package com.cipherdrop.exception;

/** Thrown when currentViews >= maxViews. Maps to 410 VIEW_LIMIT_REACHED. */
public class ViewLimitReachedException extends RuntimeException {
    public ViewLimitReachedException(String id) {
        super("View limit reached for secret: " + id);
    }
}
