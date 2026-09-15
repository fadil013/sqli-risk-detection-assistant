"""Security knowledge, not AI. Hand-curated keyword sets a human
security engineer would recognize on sight. This is the ground truth
`field_classifier.py`'s rule pass checks against, and — since no
real-world labeled SQLi dataset exists — also the source of the
synthetic training labels for its ML layer (see `ml/train_classifier.py`).

Priority matters: a field can plausibly match more than one list
("token" could be an auth token or a security token), so
`field_classifier.py` checks these in the order below, most
security-sensitive first.
"""
from __future__ import annotations

CATEGORY_PRIORITY = [
    "authentication",
    "security_token",
    "payment",
    "file_upload",
    "transaction_parameter",
    "database_identifier",
    "user_profile",
    "search_parameter",
]

AUTH_FIELDS = {
    "password", "passwd", "pwd", "pass", "username", "user", "email",
    "login", "signin", "currentpassword", "newpassword", "confirmpassword",
}

SECURITY_TOKEN_FIELDS = {
    "csrf", "token", "apikey", "api_key", "secret", "sessionid", "session_id",
    "authtoken", "auth_token", "accesstoken", "access_token", "refreshtoken",
    "jwt", "nonce",
}

PAYMENT_FIELDS = {
    "card", "cardnumber", "card_number", "cvv", "cvc", "expiry", "expirydate",
    "iban", "payment", "cardholder", "billingaddress",
}

FILE_UPLOAD_TYPES = {"file"}  # matched against input `type`, not `name`

TRANSACTION_FIELDS = {
    "quantity", "amount", "total", "invoiceid", "invoice_id",
    "transactionid", "transaction_id", "cartid", "cart_id",
}

DATABASE_IDENTIFIERS = {
    "id", "userid", "user_id", "productid", "product_id", "orderid",
    "order_id", "postid", "post_id", "categoryid", "category_id",
    "itemid", "item_id", "accountid", "account_id",
}

USER_PROFILE_FIELDS = {
    "name", "firstname", "first_name", "lastname", "last_name", "address",
    "phone", "phonenumber", "dob", "dateofbirth", "gender", "bio", "avatar",
    "profile",
}

SEARCH_FIELDS = {"search", "query", "q", "filter", "sort", "keyword", "searchterm"}

# High-value URL path segments — used by context_analyzer.py for the
# "page importance" component of the risk score (Stage 3 rules).
PAGE_IMPORTANCE_SCORES = {
    "admin": 40,
    "login": 30,
    "signin": 30,
    "checkout": 25,
    "payment": 25,
    "account": 20,
    "profile": 15,
    "search": 10,
}

FIELD_IMPORTANCE_SCORES = {
    "authentication": 30,
    "security_token": 25,
    "payment": 25,
    "database_identifier": 20,
    "transaction_parameter": 18,
    "user_profile": 12,
    "search_parameter": 10,
    "file_upload": 15,
    "unknown": 0,
}

METHOD_SCORES = {"POST": 20, "PUT": 20, "PATCH": 20, "GET": 10, "DELETE": 15}


def keyword_sets_by_category() -> dict[str, set[str]]:
    return {
        "authentication": AUTH_FIELDS,
        "security_token": SECURITY_TOKEN_FIELDS,
        "payment": PAYMENT_FIELDS,
        "transaction_parameter": TRANSACTION_FIELDS,
        "database_identifier": DATABASE_IDENTIFIERS,
        "user_profile": USER_PROFILE_FIELDS,
        "search_parameter": SEARCH_FIELDS,
    }
