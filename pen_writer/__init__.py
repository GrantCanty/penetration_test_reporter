__app_name__ = "pen writer"
__version__ = "0.1.0"

(
    SUCCESS,
    URL_ERROR,
    IP_ERROR,
    RESPONSE_ERROR
) = range(4)

ERRORS = {
    URL_ERROR: "URL provided is not valid",
    IP_ERROR: "IP address provided is not valid",
    RESPONSE_ERROR: "Error getting response from provided destination"
}