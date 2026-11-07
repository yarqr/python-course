from itertools import combinations


class Solution:
    def subsetsWithDup(self, nums: list[int]) -> list[list[int]]:
        ans: list[tuple[int, ...]] = []
        nums.sort()
        for i in range(len(nums) + 1):
            ans.extend(combinations(nums, i))
        return [list(x) for x in set(ans)]
