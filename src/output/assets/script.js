document.addEventListener('DOMContentLoaded', function() {
    // Make vulnerability items collapsible
    const vulnHeaders = document.querySelectorAll('.vulnerability-header');
    vulnHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const details = this.nextElementSibling;
            if (details && details.classList.contains('vulnerability-details')) {
                if (details.style.display === 'none' || !details.style.display) {
                    details.style.display = 'block';
                } else {
                    details.style.display = 'none';
                }
            }
        });
    });

    // Animate progress bars
    const progressBars = document.querySelectorAll('.progress-fill');
    progressBars.forEach(bar => {
        const width = bar.dataset.width || '0%';
        const percentage = parseFloat(width.replace('%', ''));

        // Create a gradient that scales with the actual progress
        let gradient;
        if (percentage <= 30) {
            // For low percentages, show mostly green
            gradient = `linear-gradient(90deg, #28a745 0%, #28a745 100%)`;
        } else if (percentage <= 60) {
            // For medium percentages, transition from green to yellow
            const yellowStart = Math.max(0, (percentage - 30) / 30 * 50);
            gradient = `linear-gradient(90deg, #28a745 0%, #28a745 ${50 - yellowStart}%, #ffc107 100%)`;
        } else {
            // For high percentages, transition through green → yellow → red
            const yellowStart = Math.max(0, 30);
            const redStart = Math.max(50, (percentage - 60) / 40 * 50 + 50);
            gradient = `linear-gradient(90deg, #28a745 0%, #28a745 ${yellowStart}%, #ffc107 ${yellowStart + 10}%, #ffc107 ${redStart - 10}%, #dc3545 100%)`;
        }

        setTimeout(() => {
            bar.style.width = width;
            bar.style.background = gradient;
        }, 100);
    });

    // Initialize heatmap tooltips
    initializeHeatmapTooltips();

    // Initialize heatmap filtering
    initializeHeatmapFiltering();

    // Initialize tabs
    initializeTabs();

    // Initialize search and pagination
    initializeVulnerabilitySearch();

    // Initialize complexity analysis pagination
    initializeComplexityAnalysis();

    // Initialize priority areas pagination
    initializePriorityAreas();
});

function initializeHeatmapTooltips() {
    const heatmapCells = document.querySelectorAll('.heatmap-cell');
    const tooltip = document.createElement('div');
    tooltip.className = 'heatmap-tooltip';
    document.body.appendChild(tooltip);

    let currentCell = null;
    let hideTimeout = null;

    const hideTooltip = () => {
        if (hideTimeout) clearTimeout(hideTimeout);
        hideTimeout = setTimeout(() => {
            tooltip.style.display = 'none';
            currentCell = null;
        }, 100);
    };

    const showTooltip = () => {
        if (hideTimeout) {
            clearTimeout(hideTimeout);
            hideTimeout = null;
        }
        tooltip.style.display = 'block';
    };

    heatmapCells.forEach(cell => {
        cell.addEventListener('mouseenter', function(e) {
            const fileName = this.dataset.file;
            const commits = this.dataset.commits;
            const authors = this.dataset.authors;
            const lastModified = this.dataset.lastModified;
            const fileUrl = this.dataset.fileUrl;

            let fileLink = fileName;
            if (fileUrl && fileUrl !== 'null') {
                fileLink = `<a href="${fileUrl}" target="_blank" style="color: #4a90e2; text-decoration: underline;">${fileName}</a>`;
            }

            tooltip.innerHTML = `
                <div><strong>${fileLink}</strong></div>
                <div>Commits: ${commits}</div>
                <div>Authors: ${authors}</div>
                <div>Last Modified: ${lastModified}</div>
            `;

            // Position tooltip relative to the cell, not following mouse
            const rect = this.getBoundingClientRect();
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;

            currentCell = this;
            tooltip.style.left = (rect.left + scrollLeft + rect.width + 10) + 'px';
            tooltip.style.top = (rect.top + scrollTop) + 'px';
            showTooltip();
        });

        cell.addEventListener('mouseleave', function() {
            hideTooltip();
        });
    });

    // Keep tooltip visible when hovering over it
    tooltip.addEventListener('mouseenter', function() {
        showTooltip();
    });

    tooltip.addEventListener('mouseleave', function() {
        hideTooltip();
    });
}

function initializeHeatmapFiltering() {
    const filterSelect = document.getElementById('extension-filter');
    if (!filterSelect) return;

    const heatmapCells = document.querySelectorAll('.heatmap-cell');

    // Collect all unique extensions from the heatmap cells
    const extensions = new Set();
    heatmapCells.forEach(cell => {
        const extension = cell.dataset.extension;
        if (extension) {
            extensions.add(extension);
        }
    });

    // Sort extensions and add them to the dropdown
    const sortedExtensions = Array.from(extensions).sort();
    sortedExtensions.forEach(ext => {
        const option = document.createElement('option');
        option.value = ext;
        option.textContent = `.${ext}`;
        filterSelect.appendChild(option);
    });

    // Add event listener for filtering
    filterSelect.addEventListener('change', function() {
        const selectedExtension = this.value;

        heatmapCells.forEach(cell => {
            if (selectedExtension === 'all' || cell.dataset.extension === selectedExtension) {
                cell.style.display = 'block';
            } else {
                cell.style.display = 'none';
            }
        });
    });
}

function initializeTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const targetId = this.dataset.target;
            showTabContent(targetId);

            // Update active tab
            tabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
        });
    });

    // Show first tab by default
    if (tabs.length > 0) {
        tabs[0].click();
    }
}

function showTabContent(contentId) {
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => {
        content.classList.remove('active');
    });

    const target = document.getElementById(contentId);
    if (target) {
        target.classList.add('active');
    }
}

function showSection(sectionId) {
    const sections = document.querySelectorAll('.tab-content');
    sections.forEach(section => {
        section.style.display = 'none';
    });

    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.classList.remove('active');
    });

    document.getElementById(sectionId).style.display = 'block';
    event.target.classList.add('active');
}

function getCommitClass(commitCount) {
    if (commitCount === 0) return 'commits-0';
    if (commitCount <= 2) return 'commits-1';
    if (commitCount <= 5) return 'commits-2';
    if (commitCount <= 10) return 'commits-3';
    if (commitCount <= 20) return 'commits-4';
    return 'commits-high';
}

function getChurnClass(commitCount) {
    if (commitCount <= 5) return 'churn-low';
    if (commitCount <= 15) return 'churn-medium';
    if (commitCount <= 30) return 'churn-high';
    return 'churn-critical';
}

// Vulnerability Search and Pagination System
let vulnerabilityState = {
    allItems: [],
    filteredItems: [],
    currentPage: 1,
    itemsPerPage: 10,
    searchTerm: '',
    severityFilter: '',
    authorFilter: '',
    sortBy: 'risk-desc'
};

function initializeVulnerabilitySearch() {
    // Get all vulnerability items
    vulnerabilityState.allItems = Array.from(document.querySelectorAll('.vulnerability-item-wrapper'));

    if (vulnerabilityState.allItems.length === 0) {
        return; // No vulnerabilities to search
    }

    // Initialize author filter options
    initializeAuthorFilter();

    // Set up event listeners
    const searchInput = document.getElementById('vulnerability-search');
    const severityFilter = document.getElementById('severity-filter');
    const authorFilter = document.getElementById('author-filter');
    const sortSelect = document.getElementById('sort-select');

    if (searchInput) {
        searchInput.addEventListener('input', handleSearch);
    }

    if (severityFilter) {
        severityFilter.addEventListener('change', handleFilter);
    }

    if (authorFilter) {
        authorFilter.addEventListener('change', handleFilter);
    }

    if (sortSelect) {
        sortSelect.addEventListener('change', handleSort);
    }

    // Set up pagination controls
    const prevButton = document.getElementById('prev-page');
    const nextButton = document.getElementById('next-page');

    if (prevButton) {
        prevButton.addEventListener('click', () => goToPage(vulnerabilityState.currentPage - 1));
    }

    if (nextButton) {
        nextButton.addEventListener('click', () => goToPage(vulnerabilityState.currentPage + 1));
    }

    // Initial render
    applyFiltersAndPagination();
}

function initializeAuthorFilter() {
    const authorFilter = document.getElementById('author-filter');
    if (!authorFilter) return;

    // Get unique authors
    const authors = new Set();
    vulnerabilityState.allItems.forEach(item => {
        const author = item.dataset.author;
        if (author) {
            authors.add(author);
        }
    });

    // Sort authors and add to filter
    Array.from(authors).sort().forEach(author => {
        const option = document.createElement('option');
        option.value = author;
        option.textContent = author;
        authorFilter.appendChild(option);
    });
}

function handleSearch(event) {
    vulnerabilityState.searchTerm = event.target.value.toLowerCase();
    vulnerabilityState.currentPage = 1;
    applyFiltersAndPagination();
}

function handleFilter() {
    const severityFilter = document.getElementById('severity-filter');
    const authorFilter = document.getElementById('author-filter');

    vulnerabilityState.severityFilter = severityFilter ? severityFilter.value : '';
    vulnerabilityState.authorFilter = authorFilter ? authorFilter.value : '';
    vulnerabilityState.currentPage = 1;
    applyFiltersAndPagination();
}

function handleSort(event) {
    vulnerabilityState.sortBy = event.target.value;
    applyFiltersAndPagination();
}

function applyFiltersAndPagination() {
    // Filter items
    vulnerabilityState.filteredItems = vulnerabilityState.allItems.filter(item => {
        // Search filter
        if (vulnerabilityState.searchTerm) {
            const searchFields = [
                item.dataset.message || '',
                item.dataset.author || '',
                item.dataset.files || ''
            ].join(' ').toLowerCase();

            if (!searchFields.includes(vulnerabilityState.searchTerm)) {
                return false;
            }
        }

        // Severity filter
        if (vulnerabilityState.severityFilter &&
            item.dataset.severity !== vulnerabilityState.severityFilter) {
            return false;
        }

        // Author filter
        if (vulnerabilityState.authorFilter &&
            item.dataset.author !== vulnerabilityState.authorFilter) {
            return false;
        }

        return true;
    });

    // Sort items
    sortItems();

    // Apply pagination
    renderPaginatedItems();
    updatePaginationControls();
    updateSearchStats();
}

function toggleFileFindings(elementId) {
    const findingsDiv = document.getElementById(elementId);
    const button = document.querySelector(`[onclick="toggleFileFindings('${elementId}')"]`);
    const icon = button.querySelector('.expand-icon');

    if (findingsDiv.style.display === 'none' || findingsDiv.style.display === '') {
        findingsDiv.style.display = 'block';
        icon.textContent = '▲';
        button.innerHTML = button.innerHTML.replace('Show', 'Hide');
    } else {
        findingsDiv.style.display = 'none';
        icon.textContent = '▼';
        button.innerHTML = button.innerHTML.replace('Hide', 'Show');
    }
}

function sortItems() {
    vulnerabilityState.filteredItems.sort((a, b) => {
        switch (vulnerabilityState.sortBy) {
            case 'risk-desc':
                // Try multiple ways to get the risk score
                let bRisk = parseFloat(b.getAttribute('data-risk-score') || '0') || 0;
                let aRisk = parseFloat(a.getAttribute('data-risk-score') || '0') || 0;

                // Fallback: try to get it from the displayed risk score element
                if (bRisk === 0) {
                    const bRiskEl = b.querySelector('.risk-score');
                    if (bRiskEl) bRisk = parseFloat(bRiskEl.textContent || '0') || 0;
                }
                if (aRisk === 0) {
                    const aRiskEl = a.querySelector('.risk-score');
                    if (aRiskEl) aRisk = parseFloat(aRiskEl.textContent || '0') || 0;
                }

                return bRisk - aRisk;

            case 'risk-asc':
                // Try multiple ways to get the risk score
                let aRiskAsc = parseFloat(a.getAttribute('data-risk-score') || '0') || 0;
                let bRiskAsc = parseFloat(b.getAttribute('data-risk-score') || '0') || 0;

                // Fallback: try to get it from the displayed risk score element
                if (aRiskAsc === 0) {
                    const aRiskEl = a.querySelector('.risk-score');
                    if (aRiskEl) aRiskAsc = parseFloat(aRiskEl.textContent || '0') || 0;
                }
                if (bRiskAsc === 0) {
                    const bRiskEl = b.querySelector('.risk-score');
                    if (bRiskEl) bRiskAsc = parseFloat(bRiskEl.textContent || '0') || 0;
                }

                return aRiskAsc - bRiskAsc;
            case 'date-desc':
                // Use actual date if available, fallback to index
                if (a.dataset.date && b.dataset.date) {
                    return new Date(b.dataset.date) - new Date(a.dataset.date);
                }
                return parseInt(b.dataset.index || 0) - parseInt(a.dataset.index || 0);
            case 'date-asc':
                if (a.dataset.date && b.dataset.date) {
                    return new Date(a.dataset.date) - new Date(b.dataset.date);
                }
                return parseInt(a.dataset.index || 0) - parseInt(b.dataset.index || 0);
            case 'author':
                return (a.dataset.author || '').localeCompare(b.dataset.author || '');
            default:
                return 0;
        }
    });
}

function renderPaginatedItems() {
    const container = document.getElementById('vulnerabilities-container');
    const noResults = document.getElementById('no-results');

    if (!container) return;

    // Hide all items first
    vulnerabilityState.allItems.forEach(item => {
        item.style.display = 'none';
    });

    // Show no results if needed
    if (vulnerabilityState.filteredItems.length === 0) {
        if (noResults) noResults.style.display = 'block';
        return;
    } else {
        if (noResults) noResults.style.display = 'none';
    }

    // Calculate pagination
    const totalPages = Math.ceil(vulnerabilityState.filteredItems.length / vulnerabilityState.itemsPerPage);
    vulnerabilityState.currentPage = Math.max(1, Math.min(vulnerabilityState.currentPage, totalPages));

    const startIndex = (vulnerabilityState.currentPage - 1) * vulnerabilityState.itemsPerPage;
    const endIndex = startIndex + vulnerabilityState.itemsPerPage;

    // Show items for current page in the correct sorted order
    const pageItems = vulnerabilityState.filteredItems.slice(startIndex, endIndex);

    // Reorder DOM elements to match sorted order
    pageItems.forEach((item, index) => {
        item.style.display = 'block';
        // Move element to correct position in DOM
        container.appendChild(item);
    });
}

function updatePaginationControls() {
    const totalPages = Math.ceil(vulnerabilityState.filteredItems.length / vulnerabilityState.itemsPerPage);
    const prevButton = document.getElementById('prev-page');
    const nextButton = document.getElementById('next-page');
    const paginationInfo = document.getElementById('pagination-info');
    const paginationContainer = document.getElementById('pagination-container');

    if (!paginationContainer) return;

    if (totalPages <= 1) {
        paginationContainer.style.display = 'none';
        return;
    } else {
        paginationContainer.style.display = 'flex';
    }

    // Update buttons
    if (prevButton) {
        prevButton.disabled = vulnerabilityState.currentPage <= 1;
    }

    if (nextButton) {
        nextButton.disabled = vulnerabilityState.currentPage >= totalPages;
    }

    // Update info
    if (paginationInfo) {
        paginationInfo.textContent = `Page ${vulnerabilityState.currentPage} of ${totalPages}`;
    }

    // Update page number buttons (create them if needed)
    updatePageNumbers(totalPages);
}

function updatePageNumbers(totalPages) {
    const pagination = document.getElementById('pagination');
    if (!pagination) return;

    // Clear existing page numbers (keep prev/next)
    const existingNumbers = pagination.querySelectorAll('.page-number');
    existingNumbers.forEach(btn => btn.remove());

    // Add page numbers (show max 5 pages around current)
    const maxVisible = 5;
    let startPage = Math.max(1, vulnerabilityState.currentPage - Math.floor(maxVisible / 2));
    let endPage = Math.min(totalPages, startPage + maxVisible - 1);

    if (endPage - startPage < maxVisible - 1) {
        startPage = Math.max(1, endPage - maxVisible + 1);
    }

    const nextButton = document.getElementById('next-page');

    for (let i = startPage; i <= endPage; i++) {
        const li = document.createElement('li');
        const button = document.createElement('button');
        button.textContent = i;
        button.className = 'page-number';
        if (i === vulnerabilityState.currentPage) {
            button.classList.add('active');
        }
        button.addEventListener('click', () => goToPage(i));
        li.appendChild(button);
        pagination.insertBefore(li, nextButton.parentElement);
    }
}

function updateSearchStats() {
    const searchStats = document.getElementById('search-stats');
    const resultsCount = document.getElementById('results-count');

    const total = vulnerabilityState.allItems.length;
    const filtered = vulnerabilityState.filteredItems.length;
    const isFiltered = vulnerabilityState.searchTerm ||
                      vulnerabilityState.severityFilter ||
                      vulnerabilityState.authorFilter;

    if (searchStats) {
        if (isFiltered) {
            searchStats.textContent = `Showing ${filtered} of ${total} vulnerabilities`;
        } else {
            searchStats.textContent = `Showing all ${total} vulnerabilities`;
        }
    }

    if (resultsCount) {
        const startIndex = (vulnerabilityState.currentPage - 1) * vulnerabilityState.itemsPerPage + 1;
        const endIndex = Math.min(startIndex + vulnerabilityState.itemsPerPage - 1, filtered);

        if (filtered > 0) {
            resultsCount.textContent = `Showing ${startIndex}-${endIndex} of ${filtered} results`;
        } else {
            resultsCount.textContent = `No results found`;
        }
    }
}

function goToPage(page) {
    const totalPages = Math.ceil(vulnerabilityState.filteredItems.length / vulnerabilityState.itemsPerPage);
    if (page >= 1 && page <= totalPages) {
        vulnerabilityState.currentPage = page;
        renderPaginatedItems();
        updatePaginationControls();
        updateSearchStats();

        // Scroll to top of results
        const container = document.getElementById('vulnerabilities-container');
        if (container) {
            container.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
}

// Complexity Analysis Pagination and Search
let complexityState = {
    allRows: [],
    filteredRows: [],
    currentPage: 1,
    itemsPerPage: 50,
    searchTerm: '',
    filenameFilter: 'all'
};

function initializeComplexityAnalysis() {
    const table = document.getElementById('complexityTable');
    if (!table) return;

    complexityState.allRows = Array.from(table.querySelectorAll('.complexity-row'));
    complexityState.filteredRows = [...complexityState.allRows];

    // Populate filename filter dropdown
    populateFilenameFilter();

    if (complexityState.allRows.length > 0) {
        applyComplexityPagination();
    }
}

function populateFilenameFilter() {
    const filterSelect = document.getElementById('complexityFilenameFilter');
    if (!filterSelect) return;

    // Get unique file extensions
    const extensions = new Set();
    complexityState.allRows.forEach(row => {
        const filename = row.dataset.filename || '';
        const parts = filename.split('.');
        if (parts.length > 1) {
            extensions.add(parts[parts.length - 1]);
        }
    });

    // Sort extensions and add to dropdown
    Array.from(extensions).sort().forEach(ext => {
        const option = document.createElement('option');
        option.value = ext;
        option.textContent = `.${ext} files`;
        filterSelect.appendChild(option);
    });
}

function searchComplexityFiles() {
    complexityState.searchTerm = document.getElementById('complexitySearch').value.toLowerCase();
    complexityState.currentPage = 1;
    applyComplexityFiltersAndSort();
}

function filterComplexityFiles() {
    complexityState.filenameFilter = document.getElementById('complexityFilenameFilter').value;
    complexityState.currentPage = 1;
    applyComplexityFiltersAndSort();
}

function sortComplexityFiles() {
    applyComplexityFiltersAndSort();
}

function applyComplexityFiltersAndSort() {
    // Apply all filters
    complexityState.filteredRows = complexityState.allRows.filter(row => {
        const filename = row.dataset.filename || '';

        // Search filter
        if (complexityState.searchTerm && !filename.includes(complexityState.searchTerm)) {
            return false;
        }

        // Extension filter
        if (complexityState.filenameFilter !== 'all') {
            const parts = filename.split('.');
            if (parts.length > 1) {
                const extension = parts[parts.length - 1];
                if (extension !== complexityState.filenameFilter) {
                    return false;
                }
            } else if (complexityState.filenameFilter !== 'no-ext') {
                return false;
            }
        }

        return true;
    });

    // Apply sorting
    const sortBy = document.getElementById('complexitySort').value;
    complexityState.filteredRows.sort((a, b) => {
        switch (sortBy) {
            case 'complexity-desc':
                return parseFloat(b.dataset.complexity || '0') - parseFloat(a.dataset.complexity || '0');
            case 'complexity-asc':
                return parseFloat(a.dataset.complexity || '0') - parseFloat(b.dataset.complexity || '0');
            case 'cognitive-desc':
                return parseFloat(b.dataset.cognitive || '0') - parseFloat(a.dataset.cognitive || '0');
            case 'cognitive-asc':
                return parseFloat(a.dataset.cognitive || '0') - parseFloat(b.dataset.cognitive || '0');
            case 'maintainability-desc':
                return parseFloat(b.dataset.maintainability || '0') - parseFloat(a.dataset.maintainability || '0');
            case 'maintainability-asc':
                return parseFloat(a.dataset.maintainability || '0') - parseFloat(b.dataset.maintainability || '0');
            case 'functions-desc':
                return parseInt(b.dataset.functions || '0') - parseInt(a.dataset.functions || '0');
            case 'lines-desc':
                return parseInt(b.dataset.lines || '0') - parseInt(a.dataset.lines || '0');
            case 'name-asc':
                return (a.dataset.filename || '').localeCompare(b.dataset.filename || '');
            case 'name-desc':
                return (b.dataset.filename || '').localeCompare(a.dataset.filename || '');
            default:
                return 0;
        }
    });

    applyComplexityPagination();
}

function changeComplexityPageSize() {
    const pageSize = document.getElementById('complexityPageSize').value;
    complexityState.itemsPerPage = pageSize === 'all' ? complexityState.filteredRows.length : parseInt(pageSize);
    complexityState.currentPage = 1;
    applyComplexityPagination();
}

function changeComplexityPage(delta) {
    const totalPages = Math.ceil(complexityState.filteredRows.length / complexityState.itemsPerPage);
    const newPage = complexityState.currentPage + delta;

    if (newPage >= 1 && newPage <= totalPages) {
        complexityState.currentPage = newPage;
        applyComplexityPagination();
    }
}

function applyComplexityPagination() {
    // Hide all rows
    complexityState.allRows.forEach(row => row.style.display = 'none');

    // Calculate pagination
    const totalPages = Math.ceil(complexityState.filteredRows.length / complexityState.itemsPerPage);
    const startIndex = (complexityState.currentPage - 1) * complexityState.itemsPerPage;
    const endIndex = startIndex + complexityState.itemsPerPage;

    // Show current page rows
    const pageRows = complexityState.filteredRows.slice(startIndex, endIndex);
    pageRows.forEach(row => row.style.display = 'table-row');

    // Update controls
    updateComplexityControls(totalPages, startIndex, Math.min(endIndex, complexityState.filteredRows.length));
}

function updateComplexityControls(totalPages, startIndex, endIndex) {
    // Update pagination info
    const paginationInfo = document.getElementById('complexityPaginationInfo');
    if (paginationInfo) {
        paginationInfo.textContent = `Showing ${startIndex + 1}-${endIndex} of ${complexityState.filteredRows.length} files`;
    }

    // Update page info
    const pageInfo = document.getElementById('complexityPageInfo');
    if (pageInfo) {
        pageInfo.textContent = `Page ${complexityState.currentPage} of ${totalPages}`;
    }

    // Update buttons
    const prevBtn = document.getElementById('complexityPrevBtn');
    const nextBtn = document.getElementById('complexityNextBtn');

    if (prevBtn) prevBtn.disabled = complexityState.currentPage <= 1;
    if (nextBtn) nextBtn.disabled = complexityState.currentPage >= totalPages;
}

// Priority Areas Pagination and Search
let priorityState = {
    allItems: [],
    filteredItems: [],
    currentPage: 1,
    itemsPerPage: 25
};

function initializePriorityAreas() {
    const list = document.getElementById('priorityAreasList');
    if (!list) return;

    priorityState.allItems = Array.from(list.querySelectorAll('.priority-area-item'));
    priorityState.filteredItems = [...priorityState.allItems];

    if (priorityState.allItems.length > 0) {
        applyPriorityPagination();
    }
}

function searchPriorityAreas() {
    const searchTerm = document.getElementById('prioritySearch').value.toLowerCase();

    priorityState.filteredItems = priorityState.allItems.filter(item => {
        const filename = item.dataset.filename || '';
        const findingTexts = Array.from(item.querySelectorAll('.finding-item'))
            .map(finding => finding.textContent.toLowerCase())
            .join(' ');

        return filename.includes(searchTerm) || findingTexts.includes(searchTerm);
    });

    priorityState.currentPage = 1;
    applyPriorityPagination();
}

function sortPriorityAreas() {
    const sortBy = document.getElementById('prioritySort').value;

    priorityState.filteredItems.sort((a, b) => {
        switch (sortBy) {
            case 'priority-desc':
            case 'findings-desc':
                return parseInt(b.dataset.totalFindings || 0) - parseInt(a.dataset.totalFindings || 0);
            case 'critical-desc':
                return parseInt(b.dataset.criticalFindings || 0) - parseInt(a.dataset.criticalFindings || 0);
            case 'name-asc':
                return (a.dataset.filename || '').localeCompare(b.dataset.filename || '');
            default:
                return 0;
        }
    });

    applyPriorityPagination();
}

function changePriorityPageSize() {
    const pageSize = document.getElementById('priorityPageSize').value;
    priorityState.itemsPerPage = pageSize === 'all' ? priorityState.filteredItems.length : parseInt(pageSize);
    priorityState.currentPage = 1;
    applyPriorityPagination();
}

function changePriorityPage(delta) {
    const totalPages = Math.ceil(priorityState.filteredItems.length / priorityState.itemsPerPage);
    const newPage = priorityState.currentPage + delta;

    if (newPage >= 1 && newPage <= totalPages) {
        priorityState.currentPage = newPage;
        applyPriorityPagination();
    }
}

function applyPriorityPagination() {
    // Hide all items
    priorityState.allItems.forEach(item => item.style.display = 'none');

    // Calculate pagination
    const totalPages = Math.ceil(priorityState.filteredItems.length / priorityState.itemsPerPage);
    const startIndex = (priorityState.currentPage - 1) * priorityState.itemsPerPage;
    const endIndex = startIndex + priorityState.itemsPerPage;

    // Show current page items
    const pageItems = priorityState.filteredItems.slice(startIndex, endIndex);
    pageItems.forEach(item => item.style.display = 'block');

    // Update controls
    updatePriorityControls(totalPages, startIndex, Math.min(endIndex, priorityState.filteredItems.length));
}

function updatePriorityControls(totalPages, startIndex, endIndex) {
    // Update pagination info
    const paginationInfo = document.getElementById('priorityPaginationInfo');
    if (paginationInfo) {
        paginationInfo.textContent = `Showing ${startIndex + 1}-${endIndex} of ${priorityState.filteredItems.length} files`;
    }

    // Update page info
    const pageInfo = document.getElementById('priorityPageInfo');
    if (pageInfo) {
        pageInfo.textContent = `Page ${priorityState.currentPage} of ${totalPages}`;
    }

    // Update buttons
    const prevBtn = document.getElementById('priorityPrevBtn');
    const nextBtn = document.getElementById('priorityNextBtn');

    if (prevBtn) prevBtn.disabled = priorityState.currentPage <= 1;
    if (nextBtn) nextBtn.disabled = priorityState.currentPage >= totalPages;
}