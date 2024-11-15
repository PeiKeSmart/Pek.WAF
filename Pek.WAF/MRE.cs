﻿using System.Collections;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;

namespace Pek.WAF;

public class MRE
{
    private static readonly ExpressionType[] _nestedOperators = new ExpressionType[]
        {ExpressionType.And, ExpressionType.AndAlso, ExpressionType.Or, ExpressionType.OrElse};

    private static readonly Lazy<MethodInfo?> _miRegexIsMatch = new(() =>
        typeof(Regex).GetMethod("IsMatch", new[] { typeof(string), typeof(string), typeof(RegexOptions) }));

    private static readonly Lazy<MethodInfo?> _miListContains = new(() =>
        typeof(IList).GetMethod("Contains", new[] { typeof(object) }));

    private static readonly Tuple<string, Lazy<MethodInfo>>[] _enumrMethodsByName =
        [
                Tuple.Create("Any", new Lazy<MethodInfo>(() => GetLinqMethod("Any", 2))),
                Tuple.Create("All", new Lazy<MethodInfo>(() => GetLinqMethod("All", 2))),
        ];
    private static readonly Lazy<MethodInfo?> _miIntTryParse = new(() =>
        typeof(Int32).GetMethod("TryParse", new Type[] { typeof(string), Type.GetType("System.Int32&") }));

    private static readonly Lazy<MethodInfo?> _miFloatTryParse = new(() =>
        typeof(Single).GetMethod("TryParse", new Type[] { typeof(string), Type.GetType("System.Single&") }));

    private static readonly Lazy<MethodInfo?> _miDoubleTryParse = new(() =>
        typeof(Double).GetMethod("TryParse", new Type[] { typeof(string), Type.GetType("System.Double&") }));

    private static readonly Lazy<MethodInfo?> _miDecimalTryParse = new(() =>
        typeof(Decimal).GetMethod("TryParse", new Type[] { typeof(string), Type.GetType("System.Decimal&") }));

    public Func<T, Boolean> CompileRule<T>(Rule r)
    {
        if (r == null) return _ => true;

        var paramUser = Expression.Parameter(typeof(T));
        var expr = GetExpressionForRule(typeof(T), r, paramUser);

        return Expression.Lambda<Func<T, bool>>(expr, paramUser).Compile();
    }

    public static Expression<Func<T, bool>> ToExpression<T>(Rule r, bool useTryCatchForNulls = true)
    {
        var paramUser = Expression.Parameter(typeof(T));
        var expr = GetExpressionForRule(typeof(T), r, paramUser, useTryCatchForNulls);

        return Expression.Lambda<Func<T, bool>>(expr, paramUser);
    }

    public static Func<T, bool> ToFunc<T>(Rule r, bool useTryCatchForNulls = true)
    {
        return ToExpression<T>(r, useTryCatchForNulls).Compile();
    }
    public static Expression<Func<object, bool>> ToExpression(Type type, Rule r)
    {
        var paramUser = Expression.Parameter(typeof(object));
        var expr = GetExpressionForRule(type, r, paramUser);

        return Expression.Lambda<Func<object, bool>>(expr, paramUser);
    }

    public static Func<object, bool> ToFunc(Type type, Rule r)
    {
        return ToExpression(type, r).Compile();
    }

    public Func<object, bool> CompileRule(Type type, Rule r)
    {
        var paramUser = Expression.Parameter(typeof(object));
        var expr = GetExpressionForRule(type, r, paramUser);

        return Expression.Lambda<Func<object, bool>>(expr, paramUser).Compile();
    }

    public Func<T, bool> CompileRules<T>(IEnumerable<Rule> rules)
    {
        var paramUser = Expression.Parameter(typeof(T));
        var expr = BuildNestedExpression(typeof(T), rules, paramUser, ExpressionType.And);
        return Expression.Lambda<Func<T, bool>>(expr, paramUser).Compile();
    }

    public Func<object, bool> CompileRules(Type type, IEnumerable<Rule> rules)
    {
        var paramUser = Expression.Parameter(type);
        var expr = BuildNestedExpression(type, rules, paramUser, ExpressionType.And);
        return Expression.Lambda<Func<object, bool>>(expr, paramUser).Compile();
    }

    // Build() in some forks
    protected static Expression GetExpressionForRule(Type type, Rule rule, ParameterExpression parameterExpression, bool useTryCatchForNulls = true)
    {
        ExpressionType nestedOperator;
        if (ExpressionType.TryParse(rule.Operator, out nestedOperator) &&
            _nestedOperators.Contains(nestedOperator) && rule.Rules != null && rule.Rules.Any())
            if (rule.Negate)
                return Expression.Not(BuildNestedExpression(type, rule.Rules, parameterExpression, nestedOperator, useTryCatchForNulls));
            else
                return BuildNestedExpression(type, rule.Rules, parameterExpression, nestedOperator, useTryCatchForNulls);
        else
        {
            if (rule.Negate)
                return Expression.Not(BuildExpr(type, rule, parameterExpression, useTryCatchForNulls));
            else
                return BuildExpr(type, rule, parameterExpression, useTryCatchForNulls);
        }
    }

    protected static Expression BuildNestedExpression(Type type, IEnumerable<Rule> rules, ParameterExpression param,
        ExpressionType operation, bool useTryCatchForNulls = true)
    {
        var expressions = rules.Select(r => GetExpressionForRule(type, r, param, useTryCatchForNulls));
        return BinaryExpression(expressions, operation);
    }

    protected static Expression BinaryExpression(IEnumerable<Expression> expressions, ExpressionType operationType)
    {
        Func<Expression, Expression, Expression> methodExp;
        switch (operationType)
        {
            case ExpressionType.Or:
                methodExp = Expression.Or;
                break;
            case ExpressionType.OrElse:
                methodExp = Expression.OrElse;
                break;
            case ExpressionType.AndAlso:
                methodExp = Expression.AndAlso;
                break;
            default:
            case ExpressionType.And:
                methodExp = Expression.And;
                break;
        }

        return expressions.Aggregate(methodExp);
    }

    private static readonly Regex _regexIndexed =
        new(@"(?'Collection'\w+)\[(?:(?'Index'\d+)|(?:['""](?'Key'\w+)[""']))\]", RegexOptions.Compiled);

    private static Expression GetProperty(Expression param, string propname)
    {
        var propExpression = param;
        var childProperties = propname.Split('.');
        var propertyType = param.Type;

        foreach (var childprop in childProperties)
        {
            var isIndexed = _regexIndexed.Match(childprop);
            if (isIndexed.Success)
            {
                var indexType = typeof(int);
                var collectionname = isIndexed.Groups["Collection"].Value;
                var collectionProp = propertyType.GetProperty(collectionname);
                if (collectionProp == null)
                    throw new RulesException(
                        $"Cannot find collection property {collectionname} in class {propertyType.Name} (\"{propname}\")");
                var collexpr = Expression.PropertyOrField(propExpression, collectionname);

                Expression expIndex;
                if (isIndexed.Groups["Index"].Success)
                {
                    var index = Int32.Parse(isIndexed.Groups["Index"].Value);
                    expIndex = Expression.Constant(index);
                }
                else
                {
                    expIndex = Expression.Constant(isIndexed.Groups["Key"].Value);
                    indexType = typeof(string);
                }

                var collectionType = collexpr.Type;
                if (collectionType.IsArray)
                {
                    propExpression = Expression.ArrayAccess(collexpr, expIndex);
                    propertyType = propExpression.Type;
                }
                else
                {
                    var getter = collectionType.GetMethod("get_Item", new Type[] { indexType });
                    if (getter == null)
                        throw new RulesException($"'{collectionname} ({collectionType.Name}) cannot be indexed");
                    propExpression = Expression.Call(collexpr, getter, expIndex);
                    propertyType = getter.ReturnType;
                }
            }
            else
            {
                var property = propertyType.GetProperty(childprop);
                if (property == null)
                    throw new RulesException(
                            $"Cannot find property {childprop} in class {propertyType.Name} (\"{propname}\")");
                propExpression = Expression.PropertyOrField(propExpression, childprop);
                propertyType = property.PropertyType;
            }
        }

        return propExpression;
    }

    private static MethodInfo? IsEnumerableOperator(String? oprator)
    {
        return (from tup in _enumrMethodsByName
                where string.Equals(oprator, tup.Item1, StringComparison.CurrentCultureIgnoreCase)
                select tup.Item2.Value).FirstOrDefault();
    }

    private static Expression BuildExpr(Type type, Rule rule, Expression param, bool useTryCatch = true)
    {
        Expression propExpression;
        Type propType;

        if (param.Type == typeof(object))
        {
            param = Expression.TypeAs(param, type);
        }

        if (string.IsNullOrEmpty(rule.MemberName)) //check is against the object itself
        {
            propExpression = param;
            propType = propExpression.Type;
        }
        else
        {
            propExpression = GetProperty(param, rule.MemberName);
            propType = propExpression.Type;
        }
        if (useTryCatch)
        {
            propExpression = Expression.TryCatch(
                Expression.Block(propExpression.Type, propExpression),
                Expression.Catch(typeof(NullReferenceException), Expression.Default(propExpression.Type))
            );
        }

        // is the operator a known .NET operator?
        ExpressionType tBinary;

        if (ExpressionType.TryParse(rule.Operator, out tBinary))
        {
            Expression right;
            var txt = rule.TargetValue as string;
            if (txt != null && txt.StartsWith("*."))
            {
                txt = txt.Substring(2);
                right = GetProperty(param, txt);
            }
            else
                right = StringToExpression(rule.TargetValue, propType);

            return Expression.MakeBinary(tBinary, propExpression, right);
        }

        switch (rule.Operator)
        {
            case "IsMatch":
                return Expression.Call(
                    _miRegexIsMatch.Value,
                    propExpression,
                    Expression.Constant(rule.TargetValue, typeof(string)),
                    Expression.Constant(RegexOptions.IgnoreCase, typeof(RegexOptions))
                );
            case "IsInteger":
                return Expression.Call(
                    _miIntTryParse.Value,
                    propExpression,
                    Expression.MakeMemberAccess(null, typeof(Placeholder).GetField("Int"))
                );
            case "IsSingle":
                return Expression.Call(
                    _miFloatTryParse.Value,
                    propExpression,
                    Expression.MakeMemberAccess(null, typeof(Placeholder).GetField("Float"))
                );
            case "IsDouble":
                return Expression.Call(
                    _miDoubleTryParse.Value,
                    propExpression,
                    Expression.MakeMemberAccess(null, typeof(Placeholder).GetField("Double"))
                );
            case "IsDecimal":
                return Expression.Call(
                    _miDecimalTryParse.Value,
                    propExpression,
                    Expression.MakeMemberAccess(null, typeof(Placeholder).GetField("Decimal"))
                );
            case "IsInInput":
                return Expression.Call(Expression.Constant(rule.Inputs.ToList()),
                                       _miListContains.Value,
                                       propExpression);
            default:
                break;
        }

        var enumrOperation = IsEnumerableOperator(rule.Operator);
        if (enumrOperation != null)
        {
            var elementType = ElementType(propType);
            var lambdaParam = Expression.Parameter(elementType, "lambdaParam");
            return rule.Rules?.Any() == true
                ? Expression.Call(enumrOperation.MakeGenericMethod(elementType),
                    propExpression,
                    Expression.Lambda(
                        BuildNestedExpression(elementType, rule.Rules, lambdaParam, ExpressionType.AndAlso),
                        lambdaParam)


                )
                : Expression.Call(enumrOperation.MakeGenericMethod(elementType), propExpression);
        }
        else //Invoke a method on the Property
        {
            var inputs = rule.Inputs.Select(x => x.GetType()).ToArray();
            var methodInfo = propType.GetMethod(rule.Operator, inputs);
            List<Expression> expressions = new();

            if (methodInfo == null)
            {
                methodInfo = propType.GetMethod(rule.Operator);
                if (methodInfo != null)
                {
                    var parameters = methodInfo.GetParameters();
                    var i = 0;
                    foreach (var item in rule.Inputs)
                    {
                        expressions.Add(MRE.StringToExpression(item, parameters[i].ParameterType));
                        i++;
                    }
                }
            }
            else
                expressions.AddRange(rule.Inputs.Select(Expression.Constant));
            if (methodInfo == null)
                throw new RulesException($"'{rule.Operator}' is not a method of '{propType.Name}");


            if (!methodInfo.IsGenericMethod)
                inputs = null; //Only pass in type information to a Generic Method
            var callExpression = Expression.Call(propExpression, rule.Operator, inputs, expressions.ToArray());
            if (useTryCatch)
            {
                return Expression.TryCatch(
                Expression.Block(typeof(bool), callExpression),
                Expression.Catch(typeof(NullReferenceException), Expression.Constant(false))
                );
            }
            else
                return callExpression;
        }
    }

    private static MethodInfo? GetLinqMethod(string name, int numParameter)
    {
        return typeof(Enumerable).GetMethods(BindingFlags.Static | BindingFlags.Public)
            .FirstOrDefault(m => m.Name == name && m.GetParameters().Length == numParameter);
    }

    private static Expression StringToExpression(Object? value, Type propType)
    {
        Debug.Assert(propType != null);

        object? safevalue;
        var valuetype = propType;
        var txt = value as string;
        if (value == null)
        {
            safevalue = null;
        }
        else if (txt != null)
        {
            if (txt.ToLower() == "null")
                safevalue = null;
            else if (propType.IsEnum)
                safevalue = Enum.Parse(propType, txt);
            else
            {
                if (propType.Name == "Nullable`1")
                    valuetype = Nullable.GetUnderlyingType(propType);

                safevalue = IsTime(txt, propType) ?? Convert.ChangeType(value, valuetype);
            }
        }
        else
        {
            if (propType.Name == "Nullable`1")
                valuetype = Nullable.GetUnderlyingType(propType);
            safevalue = Convert.ChangeType(value, valuetype);
        }

        return Expression.Constant(safevalue, propType);
    }

    private static readonly Regex reNow = new(@"#NOW([-+])(\d+)([SMHDY])", RegexOptions.IgnoreCase
                                                                            | RegexOptions.Compiled
                                                                            | RegexOptions.Singleline);

    private static DateTime? IsTime(string text, Type targetType)
    {
        if (targetType != typeof(DateTime) && targetType != typeof(DateTime?))
            return null;

        var match = reNow.Match(text);
        if (!match.Success)
            return null;

        var amt = Int32.Parse(match.Groups[2].Value);
        if (match.Groups[1].Value == "-")
            amt = -amt;

        switch (Char.ToUpperInvariant(match.Groups[3].Value[0]))
        {
            case 'S':
                return DateTime.Now.AddSeconds(amt);
            case 'M':
                return DateTime.Now.AddMinutes(amt);
            case 'H':
                return DateTime.Now.AddHours(amt);
            case 'D':
                return DateTime.Now.AddDays(amt);
            case 'Y':
                return DateTime.Now.AddYears(amt);
        }
        // it should not be possible to reach here.	
        throw new ArgumentException();
    }

    private static Type ElementType(Type seqType)
    {
        var ienum = FindIEnumerable(seqType);
        if (ienum == null) return seqType;
        return ienum.GetGenericArguments()[0];
    }

    private static Type? FindIEnumerable(Type seqType)
    {
        if (seqType == null || seqType == typeof(string))
            return null;
        if (seqType.IsArray)
            return typeof(IEnumerable<>).MakeGenericType(seqType.GetElementType());
        if (seqType.IsGenericType)
        {
            foreach (var arg in seqType.GetGenericArguments())
            {
                var ienum = typeof(IEnumerable<>).MakeGenericType(arg);
                if (ienum.IsAssignableFrom(seqType))
                {
                    return ienum;
                }
            }
        }

        var ifaces = seqType.GetInterfaces();
        foreach (var iface in ifaces)
        {
            var ienum = FindIEnumerable(iface);
            if (ienum != null)
                return ienum;
        }

        if (seqType.BaseType != null && seqType.BaseType != typeof(object))
        {
            return FindIEnumerable(seqType.BaseType);
        }

        return null;
    }
    public enum OperatorType
    {
        InternalString = 1,
        ObjectMethod = 2,
        Comparison = 3,
        Logic = 4
    }
    public class Operator
    {
        public String? Name { get; set; }
        public OperatorType Type { get; set; }
        public int NumberOfInputs { get; set; }
        public bool SimpleInputs { get; set; }
    }

    public class Member
    {
        public String? Name { get; set; }
        public String? Type { get; set; }
        public List<Operator>? PossibleOperators { get; set; }
        public static bool IsSimpleType(Type type)
        {
            return
                type.IsPrimitive ||
                new Type[] {
                        typeof(Enum),
                        typeof(String),
                        typeof(Decimal),
                        typeof(DateTime),
                        typeof(DateTimeOffset),
                        typeof(TimeSpan),
                        typeof(Guid)
                }.Contains(type) ||
                Convert.GetTypeCode(type) != TypeCode.Object ||
                (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Nullable<>) && IsSimpleType(type.GetGenericArguments()[0]))
                ;
        }
        public static BindingFlags flags = BindingFlags.Instance | BindingFlags.Public;
        public static List<Member> GetFields(Type type, String? memberName = null, String? parentPath = null)
        {
            List<Member> toReturn = new();
            var fi = new Member
            {
                Name = string.IsNullOrEmpty(parentPath) ? memberName : $"{parentPath}.{memberName}",
                Type = type.ToString()
            };
            fi.PossibleOperators = Member.Operators(type, string.IsNullOrEmpty(fi.Name));
            toReturn.Add(fi);
            if (!Member.IsSimpleType(type))
            {
                var fields = type.GetFields(Member.flags);
                var properties = type.GetProperties(Member.flags);
                foreach (var field in fields)
                {
                    String? useParentName = null;
                    var name = Member.ValidateName(field.Name, type, memberName, fi.Name, parentPath, out useParentName);
                    toReturn.AddRange(GetFields(field.FieldType, name, useParentName));
                }
                foreach (var prop in properties)
                {
                    String? useParentName = null;
                    var name = Member.ValidateName(prop.Name, type, memberName, fi.Name, parentPath, out useParentName);
                    toReturn.AddRange(GetFields(prop.PropertyType, name, useParentName));
                }
            }
            return toReturn;
        }
        private static String ValidateName(String name, Type parentType, String? parentName, String? parentPath, String? grandparentPath, out String? useAsParentPath)
        {
            if (name == "Item" && IsGenericList(parentType))
            {
                useAsParentPath = grandparentPath;
                return parentName + "[0]";
            }
            else
            {
                useAsParentPath = parentPath;
                return name;
            }
        }

        public static bool IsGenericList(Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException("type");
            }
            foreach (var @interface in type.GetInterfaces())
            {
                if (@interface.IsGenericType)
                {
                    if (@interface.GetGenericTypeDefinition() == typeof(ICollection<>))
                    {
                        // if needed, you can also return the type used as generic argument
                        return true;
                    }
                }
            }
            return false;
        }
        private static string[] logicOperators = new string[] {
                    mreOperator.And.ToString("g"),
                    mreOperator.AndAlso.ToString("g"),
                    mreOperator.Or.ToString("g"),
                    mreOperator.OrElse.ToString("g")
                };
        private static string[] comparisonOperators = new string[] {
                    mreOperator.Equal.ToString("g"),
                    mreOperator.GreaterThan.ToString("g"),
                    mreOperator.GreaterThanOrEqual.ToString("g"),
                    mreOperator.LessThan.ToString("g"),
                    mreOperator.LessThanOrEqual.ToString("g"),
                    mreOperator.NotEqual.ToString("g"),
                };

        private static string[] hardCodedStringOperators = new string[] {
                    mreOperator.IsMatch.ToString("g"),
                    mreOperator.IsInteger.ToString("g"),
                    mreOperator.IsSingle.ToString("g"),
                    mreOperator.IsDouble.ToString("g"),
                    mreOperator.IsDecimal.ToString("g"),
                    mreOperator.IsInInput.ToString("g"),
                };
        public static List<Operator> Operators(Type type, bool addLogicOperators = false, bool noOverloads = true)
        {
            List<Operator> operators = new();
            if (addLogicOperators)
            {
                operators.AddRange(logicOperators.Select(x => new Operator() { Name = x, Type = OperatorType.Logic }));
            }

            if (type == typeof(String))
            {
                operators.AddRange(hardCodedStringOperators.Select(x => new Operator() { Name = x, Type = OperatorType.InternalString }));
            }
            else if (Member.IsSimpleType(type))
            {
                operators.AddRange(comparisonOperators.Select(x => new Operator() { Name = x, Type = OperatorType.Comparison }));
            }
            var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance);
            foreach (var method in methods)
            {
                if (method.ReturnType == typeof(Boolean) && !method.Name.StartsWith("get_") && !method.Name.StartsWith("set_") && !method.Name.StartsWith("_op"))
                {
                    var paramaters = method.GetParameters();
                    var op = new Operator()
                    {
                        Name = method.Name,
                        Type = OperatorType.ObjectMethod,
                        NumberOfInputs = paramaters.Length,
                        SimpleInputs = paramaters.All(x => Member.IsSimpleType(x.ParameterType))
                    };
                    if (noOverloads)
                    {
                        var existing = operators.FirstOrDefault(x => x.Name == op.Name && x.Type == op.Type);
                        if (existing == null)
                            operators.Add(op);
                        else if (existing.NumberOfInputs > op.NumberOfInputs)
                        {
                            operators[operators.IndexOf(existing)] = op;
                        }
                    }
                    else
                        operators.Add(op);
                }
            }
            return operators;
        }
    }

}

[DataContract]
public class Rule
{
    public Rule()
    {
    }

    [DataMember] public String? MemberName { get; set; }
    [DataMember] public String? Operator { get; set; }
    [DataMember] public Object? TargetValue { get; set; }
    [DataMember] public IList<Rule>? Rules { get; set; }
    [DataMember] public IList<Object>? Inputs { get; set; }
    [DataMember] public Boolean Negate { get; set; }

    public static Rule operator |(Rule lhs, Rule rhs)
    {
        var rule = new Rule { Operator = "Or" };
        return MergeRulesInto(rule, lhs, rhs);
    }

    public static Rule operator &(Rule lhs, Rule rhs)
    {
        var rule = new Rule { Operator = "AndAlso" };
        return MergeRulesInto(rule, lhs, rhs);
    }

    private static Rule MergeRulesInto(Rule target, Rule lhs, Rule rhs)
    {
        target.Rules = new List<Rule>();

        if (lhs.Rules != null && lhs.Operator == target.Operator) // left is multiple
        {
            target.Rules.AddRange(lhs.Rules);
            if (rhs.Rules != null && rhs.Operator == target.Operator)
                target.Rules.AddRange(rhs.Rules); // left & right are multiple
            else
                target.Rules.Add(rhs); // left multi, right single
        }
        else if (rhs.Rules != null && rhs.Operator == target.Operator)
        {
            target.Rules.Add(lhs); // left single, right multi
            target.Rules.AddRange(rhs.Rules);
        }
        else
        {
            target.Rules.Add(lhs);
            target.Rules.Add(rhs);
        }


        return target;
    }

    public static Rule Create(string member, mreOperator oper, object target)
    {
        return new Rule { MemberName = member, TargetValue = target, Operator = oper.ToString() };
    }

    public static Rule MethodOnChild(string member, string methodName, params object[] inputs)
    {
        return new Rule { MemberName = member, Inputs = inputs.ToList(), Operator = methodName };
    }

    public static Rule Method(string methodName, params object[] inputs)
    {
        return new Rule { Inputs = inputs.ToList(), Operator = methodName };
    }

    public static Rule Any(string member, Rule rule)
    {
        return new Rule { MemberName = member, Operator = "Any", Rules = new List<Rule> { rule } };
    }

    public static Rule All(string member, Rule rule)
    {
        return new Rule { MemberName = member, Operator = "All", Rules = new List<Rule> { rule } };
    }

    public static Rule IsInteger(string member) => new() { MemberName = member, Operator = "IsInteger" };
    public static Rule IsFloat(string member) => new() { MemberName = member, Operator = "IsSingle" };
    public static Rule IsDouble(string member) => new() { MemberName = member, Operator = "IsDouble" };
    public static Rule IsSingle(string member) => new() { MemberName = member, Operator = "IsSingle" };
    public static Rule IsDecimal(string member) => new() { MemberName = member, Operator = "IsDecimal" };



    public override string ToString()
    {
        if (TargetValue != null)
            return $"{MemberName} {Operator} {TargetValue}";

        if (Rules != null)
        {
            if (Rules.Count == 1)
                return $"{MemberName} {Operator} ({Rules[0]})";
            else
                return $"{MemberName} {Operator} (Rules)";
        }

        if (Inputs != null)
        {
            return $"{MemberName} {Operator} (Inputs)";
        }

        return $"{MemberName} {Operator}";
    }
}

internal static class Placeholder
{
    public static int Int = 0;
    public static float Float = 0.0f;
    public static double Double = 0.0;
    public static decimal Decimal = 0.0m;
}

// Nothing specific to MRE.  Can be moved to a more common location
public static class IListExtensions
{
    public static void AddRange<T>(this IList<T> collection, IEnumerable<T> newValues)
    {
        foreach (var item in newValues)
            collection.Add(item);
    }
}

public class RulesException : ApplicationException
{
    public RulesException()
    {
    }

    public RulesException(string message) : base(message)
    {
    }

    public RulesException(string message, Exception innerException) : base(message, innerException)
    {
    }
}



//
// Summary:
//     Describes the node types for the nodes of an expression tree.
public enum mreOperator
{
    //
    // Summary:
    //     An addition operation, such as a + b, without overflow checking, for numeric
    //     operands.
    Add = 0,
    //
    // Summary:
    //     A bitwise or logical AND operation, such as (a & b) in C# and (a And b) in Visual
    //     Basic.
    And = 2,
    //
    // Summary:
    //     A conditional AND operation that evaluates the second operand only if the first
    //     operand evaluates to true. It corresponds to (a && b) in C# and (a AndAlso b)
    //     in Visual Basic.
    AndAlso = 3,
    //
    // Summary:
    //     A node that represents an equality comparison, such as (a == b) in C# or (a =
    //     b) in Visual Basic.
    Equal = 13,
    //
    // Summary:
    //     A "greater than" comparison, such as (a > b).
    GreaterThan = 15,
    //
    // Summary:
    //     A "greater than or equal to" comparison, such as (a >= b).
    GreaterThanOrEqual = 16,
    //
    // Summary:
    //     A "less than" comparison, such as (a < b).
    LessThan = 20,
    //
    // Summary:
    //     A "less than or equal to" comparison, such as (a <= b).
    LessThanOrEqual = 21,
    //
    // Summary:
    //     An inequality comparison, such as (a != b) in C# or (a <> b) in Visual Basic.
    NotEqual = 35,
    //
    // Summary:
    //     A bitwise or logical OR operation, such as (a | b) in C# or (a Or b) in Visual
    //     Basic.
    Or = 36,
    //
    // Summary:
    //     A short-circuiting conditional OR operation, such as (a || b) in C# or (a OrElse
    //     b) in Visual Basic.
    OrElse = 37,
    /// <summary>
    /// Checks that a string value matches a Regex expression
    /// </summary>
    IsMatch = 100,
    /// <summary>
    /// Checks that a value can be 'TryParsed' to an Int32
    /// </summary>
    IsInteger = 101,
    /// <summary>
    /// Checks that a value can be 'TryParsed' to a Single
    /// </summary>
    IsSingle = 102,
    /// <summary>
    /// Checks that a value can be 'TryParsed' to a Double
    /// </summary>
    IsDouble = 103,
    /// <summary>
    /// Checks that a value can be 'TryParsed' to a Decimal
    /// </summary>
    IsDecimal = 104,
    /// <summary>
    /// Checks if the value of the property is in the input list
    /// </summary>
    IsInInput = 105
}


public class RuleValue<T>
{
    public T? Value { get; set; }
    public List<Rule>? Rules { get; set; }
}

public class RuleValueString : RuleValue<string>
{
}