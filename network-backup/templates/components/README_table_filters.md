# Table Filters Component

Reusable table filtering component for provedor and IP address search.

## Usage

### 1. Include the filter HTML component

In your template, include the filter component:

```jinja
{% set filter_id = 'myFilter' %}
{% set show_provedor_filter = true %}
{% set show_ip_search = true %}
{% set ip_placeholder = 'Buscar por IP...' %}
{% include 'components/table_filters.html' %}
```

**Parameters:**
- `filter_id` (required): Unique identifier for this filter instance (e.g., 'backup', 'device', 'myTable')
- `provedores` (required): List of provedores to populate the dropdown (should be available in template context)
- `show_provedor_filter` (optional, default: true): Show/hide the provedor dropdown
- `show_ip_search` (optional, default: false): Show/hide the IP search input
- `ip_placeholder` (optional, default: 'Buscar por IP...'): Placeholder text for IP search

### 2. Add data attributes to table rows

Your table rows must have `data-provedor` attribute (and `data-ip` if using IP search):

```html
<tr data-provedor="OLLA" data-ip="10.2.19.0">
    <!-- table cells -->
</tr>
```

### 3. Initialize the JavaScript filter

In your template's `{% block extra_js %}`:

```javascript
document.addEventListener('DOMContentLoaded', function () {
    const myFilter = new TableFilter({
        filterId: 'myFilter',  // Must match the filter_id from step 1
        tableBodyId: 'myTableBody',  // ID of your tbody element
        countSpanId: 'visibleCount',  // ID of span showing visible count
        totalCount: 100,  // Total number of items
        filters: {
            provedor: true,  // Enable provedor filter
            ip: true  // Enable IP search filter
        }
    });
});
```

### 4. Add count display (optional)

In your table footer:

```html
<div>Mostrando <span id="visibleCount">10</span> de 100 itens</div>
```

## Example: Complete Implementation

```jinja
<!-- In your template -->
<div class="table-header">
    <h5>My Table</h5>
    <div class="table-actions">
        {% set filter_id = 'myTable' %}
        {% set show_provedor_filter = true %}
        {% set show_ip_search = true %}
        {% include 'components/table_filters.html' %}
    </div>
</div>

<table>
    <thead>...</thead>
    <tbody id="myTableBody">
        {% for item in items %}
        <tr data-provedor="{{ item.provedor or 'Sem_Provedor' }}" data-ip="{{ item.ip_address }}">
            <!-- cells -->
        </tr>
        {% endfor %}
    </tbody>
</table>

<div>Mostrando <span id="visibleCount">{{ items|length }}</span> de {{ items|length }} itens</div>
```

```javascript
// In {% block extra_js %}
<script>
document.addEventListener('DOMContentLoaded', function () {
    const myTableFilter = new TableFilter({
        filterId: 'myTable',
        tableBodyId: 'myTableBody',
        countSpanId: 'visibleCount',
        totalCount: {{ items|length }},
        filters: {
            provedor: true,
            ip: true
        }
    });
});
</script>
```

## Features

- ✅ Provedor dropdown filter
- ✅ IP address search (real-time, case-insensitive, partial match)
- ✅ Combined filtering (both filters work together)
- ✅ Automatic count updates
- ✅ Fully reusable and configurable

