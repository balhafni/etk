from etk.extractors.regex_extractor import RegexExtractor


class AttachmentExtractor(RegexExtractor):
    """
    **Description**
           This class inherits RegexExtractor and predefines the ip address pattern

    Examples:
        ::

            ip_address_extractor = IPAddressExtractor()
            ip_address_extractor.extract(text=input_doc)
    """
    def __init__(self):
        attachment_pattern = "(?:.+?(?=attachment))?attachment\s(([\'\w\.\']+)?)"
        RegexExtractor.__init__(self, pattern=attachment_pattern, extractor_name="attachment")
