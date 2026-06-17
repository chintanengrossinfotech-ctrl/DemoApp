"""
Render helpers — second hop of the cross-file flaw (#5).

`render_profile` drops the (only angle-bracket-"cleaned") value directly into an
HTML *attribute* using string formatting. Even with angle brackets stripped, an
attacker breaks out of the attribute with a quote and adds an event handler:

    value:  " onmouseover=alert(1) x="
    result: <div data-name="" onmouseover=alert(1) x="">

So the flaw requires reasoning across routes.py -> sanitize.py -> render.py.
A single-file scan of any one of these looks fine.
"""


def render_profile(cleaned_name: str) -> str:
    # Attribute-context injection: quotes are not escaped.
    return '<div class="profile" data-name="' + cleaned_name + '">profile</div>'
