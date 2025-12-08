__app_name__ = "pen_writer"
__version__ = "0.1.0"

(
    SUCCESS,
    TARGET_ERROR,
    RESPONSE_ERROR,
    DIRECTORY_ERROR,
    LLM_ERROR,
) = range(5)

ERRORS = {
    TARGET_ERROR: "URL provided is not valid",
    RESPONSE_ERROR: "Error getting response from provided target",
    DIRECTORY_ERROR: "Error with the provided directory",
    LLM_ERROR: "Error when generating a response from the LLM"
}