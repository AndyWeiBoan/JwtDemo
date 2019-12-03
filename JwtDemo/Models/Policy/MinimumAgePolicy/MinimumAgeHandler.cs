using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtDemo.Models.Policy.MinimumAgePolicy {

    public class MinimumAgeHandler : AuthorizationHandler<MinimumAge> {
        
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumAge requirement) {
            var user = context.User;
            var claim = context.User.FindFirst("Age");
            if (claim == null)
                context.Fail();

            if (!int.TryParse(claim.Value, out var age))
                context.Fail();

            if (age < requirement.Age) {
                context.Fail();
            }
            context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
