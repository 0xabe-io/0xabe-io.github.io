---
layout: page
title: Categories
permalink: /categories/
---
{% for category in site.categories %}
  <p>
    <li>{{ category | first }}
      <ul>
      {% for posts in category %}
        {% for post in posts %}
          {% if post.url %}
            <li><a href="{{ post.url }}">{{ post.title }}</a></li>
          {% endif %}
        {% endfor %}
      {% endfor %}
      </ul>
    </li>
  </p>
{% endfor %}

