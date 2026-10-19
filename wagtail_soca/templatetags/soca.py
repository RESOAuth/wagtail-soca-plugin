from django import template

from wagtail_soca.config import enabled

register = template.Library()


@register.simple_tag
def soca_enabled():
    return enabled()
