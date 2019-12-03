using Microsoft.AspNetCore.Authorization;

namespace JwtDemo.Models.Policy.MinimumAgePolicy {
    public class MinimumAge : IAuthorizationRequirement {

        public readonly int Age;

        public MinimumAge(int age) {
            this.Age = age;
        }
    }
}
