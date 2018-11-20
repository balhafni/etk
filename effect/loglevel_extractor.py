from etk.extractors.regex_extractor import RegexExtractor


class LoglevelExtractor(RegexExtractor):
    """
    **Description**
           This class inherits RegexExtractor and predefines the ip address pattern

    Examples:
        ::

            ip_address_extractor = IPAddressExtractor()
            ip_address_extractor.extract(text=input_doc)
    """
    def __init__(self):
        log_level_pattern = "(?:.*)\;([\w]+)"
        RegexExtractor.__init__(self, pattern=log_level_pattern, extractor_name="log level")
