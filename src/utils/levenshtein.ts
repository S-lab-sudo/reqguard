/**
 * ReqGuard Levenshtein Distance Algorithm
 * Highly optimized, zero-dependency implementation.
 * Uses single-row dynamic programming for O(min(m,n)) space complexity.
 */

/**
 * Calculate the Levenshtein distance between two strings.
 * This is the minimum number of single-character edits (insertions,
 * deletions, or substitutions) required to transform one string into another.
 * 
 * Optimizations:
 * - Early exit for identical strings
 * - Early exit when one string is empty
 * - Always iterate over shorter string for inner loop
 * - Single row DP array (O(min(m,n)) space)
 * - Avoid function call overhead
 * 
 * @param a First string
 * @param b Second string
 * @returns The edit distance between the two strings
 */
export function levenshtein(a: string, b: string): number {
    // FAST PATH: Identical strings
    if (a === b) {
        return 0;
    }

    const aLen = a.length;
    const bLen = b.length;

    // FAST PATH: One string is empty
    if (aLen === 0) {
        return bLen;
    }
    if (bLen === 0) {
        return aLen;
    }

    // Ensure we iterate over shorter string in inner loop (optimization)
    // This gives O(min(m,n)) space complexity
    let short: string;
    let long: string;
    let shortLen: number;
    let longLen: number;

    if (aLen <= bLen) {
        short = a;
        long = b;
        shortLen = aLen;
        longLen = bLen;
    } else {
        short = b;
        long = a;
        shortLen = bLen;
        longLen = aLen;
    }

    // FAST PATH: Length difference exceeds any reasonable typosquat threshold
    // This is a heuristic - if strings differ by more than 5 chars, 
    // distance is at least that difference
    if (longLen - shortLen > 5) {
        return longLen - shortLen;
    }

    // Single row DP array
    // row[j] represents the distance for transforming short[0..j-1] to long[0..i-1]
    const row: number[] = new Array<number>(shortLen + 1);

    // Initialize first row: cost of inserting each character
    for (let j = 0; j <= shortLen; j++) {
        row[j] = j;
    }

    // Fill in the rest of the matrix row by row
    for (let i = 1; i <= longLen; i++) {
        // Previous diagonal value (top-left in full matrix)
        let previousDiagonal = row[0];
        row[0] = i;

        const longChar = long.charCodeAt(i - 1);

        for (let j = 1; j <= shortLen; j++) {
            const shortChar = short.charCodeAt(j - 1);

            // Save current value before overwriting
            const temp = row[j];

            if (longChar === shortChar) {
                // Characters match: no operation needed
                row[j] = previousDiagonal;
            } else {
                // Minimum of:
                // - row[j-1] + 1: insertion
                // - row[j] + 1: deletion  
                // - previousDiagonal + 1: substitution
                const insertion = row[j - 1] + 1;
                const deletion = row[j] + 1;
                const substitution = previousDiagonal + 1;

                // Inline min3 to avoid function call overhead
                row[j] = insertion < deletion
                    ? (insertion < substitution ? insertion : substitution)
                    : (deletion < substitution ? deletion : substitution);
            }

            previousDiagonal = temp;
        }
    }

    return row[shortLen];
}

/**
 * Check if two strings are similar (edit distance <= threshold).
 * More efficient than computing full distance when you only need boolean result.
 * 
 * @param a First string
 * @param b Second string  
 * @param threshold Maximum allowed distance
 * @returns True if distance is less than or equal to threshold
 */
export function isSimilar(a: string, b: string, threshold: number): boolean {
    // FAST PATH: Same string
    if (a === b) {
        return true;
    }

    // FAST PATH: Length difference exceeds threshold
    const lenDiff = Math.abs(a.length - b.length);
    if (lenDiff > threshold) {
        return false;
    }

    // Full calculation
    return levenshtein(a, b) <= threshold;
}
