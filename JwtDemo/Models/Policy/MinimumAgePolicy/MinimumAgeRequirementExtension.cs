using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace JwtDemo.Models.Policy.MinimumAgePolicy {
    public static class MinimumAgeRequirementExtension {
        public static IServiceCollection AddMinimumAgeRequirement(this IServiceCollection services, int age) {
            services.AddAuthorization(options => options.AddPolicy("MinimumAge", policy => policy.AddRequirements(new MinimumAge(age))));
            return services.AddTransient<IAuthorizationHandler, MinimumAgeHandler>();
        }
    }
}
