from etk.extractors.regex_extractor import RegexExtractor


class SpamResExtractor(RegexExtractor):
    """
    **Description**
           This class inherits RegexExtractor and predefines the ip address pattern

    Examples:
        ::

            ip_address_extractor = IPAddressExtractor()
            ip_address_extractor.extract(text=input_doc)
    """
    def __init__(self):
        spam_res_pattern = "(?:.+?(?=using engine:))?using engine:\s[\w]+\s[\w]+\s(([\w]+)?)"
        RegexExtractor.__init__(self, pattern=spam_res_pattern, extractor_name="spam res")
