__app_name__ = "pen_writer"
__version__ = "0.1.0"

(
    SUCCESS,
    TARGET_ERROR,
    RESPONSE_ERROR
) = range(3)

ERRORS = {
    TARGET_ERROR: "URL provided is not valid",
    RESPONSE_ERROR: "Error getting response from provided target"
}