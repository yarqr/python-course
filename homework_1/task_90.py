from itertools import combinations


class Solution:
    def subsetsWithDup(self, nums: list[int]) -> list[list[int]]:
        ans = []
        nums.sort()
        for i in range(len(nums) + 1):
            ans.extend(combinations(nums, i))
        return list(map(lambda x: list(x), set(ans)))
