/**
 * Reusable table filter functionality
 * 
 * Usage:
 * const tableFilter = new TableFilter({
 *     filterId: 'backup',  // Unique ID prefix for filter elements
 *     tableBodyId: 'backupsTableBody',  // ID of tbody element
 *     countSpanId: 'visibleBackupCount',  // ID of span showing visible count
 *     totalCount: 100,  // Total number of items
 *     filters: {
 *         provedor: true,  // Enable provedor filter
 *         ip: true  // Enable IP search filter
 *     }
 * });
 */

class TableFilter {
    constructor(options) {
        this.filterId = options.filterId;
        this.tableBodyId = options.tableBodyId;
        this.countSpanId = options.countSpanId;
        this.totalCount = options.totalCount || 0;
        this.filters = options.filters || { provedor: true, ip: false };

        this.provedorSelect = null;
        this.ipSearch = null;
        this.tableBody = null;
        this.countSpan = null;

        this.init();
    }

    init() {
        if (this.filters.provedor) {
            this.provedorSelect = document.getElementById(`${this.filterId}ProvedorFilter`);
        }

        if (this.filters.ip) {
            this.ipSearch = document.getElementById(`${this.filterId}IpSearch`);
        }

        this.tableBody = document.getElementById(this.tableBodyId);
        this.countSpan = document.getElementById(this.countSpanId);

        if (this.provedorSelect) {
            this.provedorSelect.addEventListener('change', () => this.filter());
        }

        if (this.ipSearch) {
            this.ipSearch.addEventListener('input', () => this.filter());
        }
    }

    filter() {
        if (!this.tableBody) return;

        const selectedProvedor = this.provedorSelect ? this.provedorSelect.value : '';
        const searchIp = this.ipSearch ? this.ipSearch.value.toLowerCase().trim() : '';
        const rows = this.tableBody.querySelectorAll('tr');
        let visibleCount = 0;

        rows.forEach(row => {
            let provedorMatch = true;
            let ipMatch = true;

            if (this.filters.provedor && selectedProvedor) {
                const rowProvedor = row.getAttribute('data-provedor') || 'Sem_Provedor';
                provedorMatch = rowProvedor === selectedProvedor;
            }

            if (this.filters.ip && searchIp) {
                const rowIp = (row.getAttribute('data-ip') || '').toLowerCase();
                ipMatch = rowIp.includes(searchIp);
            }

            if (provedorMatch && ipMatch) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        if (this.countSpan) {
            this.countSpan.textContent = visibleCount;
        }
    }

    reset() {
        if (this.provedorSelect) {
            this.provedorSelect.value = '';
        }
        if (this.ipSearch) {
            this.ipSearch.value = '';
        }
        this.filter();
    }
}

