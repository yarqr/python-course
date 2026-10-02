class Solution:
    def findContentChildren(self, g: list[int], s: list[int]) -> int:
        g.sort()
        s.sort()
        i, j, ans = 0, 0, 0
        while i < len(g) and j < len(s):
            if s[j] >= g[i]:
                ans += 1
                i, j = i + 1, j + 1
            else:
                j += 1
        return ans
